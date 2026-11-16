//! Live PostgreSQL check of the DDL that lowering writes.
//!
//! Env-gated and honest like the sibling database suite: without a reachable
//! server the test prints a SKIP line and passes, so a green run never fakes
//! what actually executed.
//!
//! ```sh
//! OPUROM_TEST_PG=1 \
//! OPUROM_TEST_PG_HOST=127.0.0.1 OPUROM_TEST_PG_PORT=5432 \
//! OPUROM_TEST_PG_USER=postgres OPUROM_TEST_PG_DB=opurom_test \
//! cargo test --test pg_schema
//! ```

use std::fs;
use std::path::PathBuf;

use opurom_db::PgConnection;
use opurom_server::codegen::lower_service;

const ENABLE_ENV: &str = "OPUROM_TEST_PG";

/// The canonical keyword set, space separated: each word becomes one column
/// of a single generated table, so a set member that never reaches a quoting
/// call site comes back as a live syntax error here, while PostgreSQL's
/// ordinary identifiers must still parse bare.
const KEYWORD_UNIVERSE: &str = concat!(
    "abort absent absolute access action add admin after aggregate all also alter always ",
    "analyse analyze and any array as asc asensitive assertion assignment asymmetric at ",
    "atomic attach attribute authorization backward before begin between bigint binary bit ",
    "boolean both breadth by cache call called cascade cascaded case cast catalog chain char ",
    "character characteristics check checkpoint class close cluster coalesce collate ",
    "collation column columns comment comments commit committed compression concurrently ",
    "conditional configuration conflict connection constraint constraints content continue ",
    "conversion copy cost create cross csv cube current current_catalog current_date ",
    "current_role current_schema current_time current_timestamp current_user cursor cycle ",
    "data database day deallocate dec decimal declare default defaults deferrable deferred ",
    "definer delete delimiter delimiters depends depth desc detach dictionary disable discard ",
    "distinct do document domain double drop each else empty enable encoding encrypted end ",
    "enforced enum error escape event except exclude excluding exclusive execute exists ",
    "explain expression extension external extract false family fetch filter finalize first ",
    "float following for force foreign format forward freeze from full function functions ",
    "generated global grant granted greatest group grouping groups handler having header hold ",
    "hour identity if ignore ilike immediate immutable implicit import in include including ",
    "increment indent index indexes inherit inherits initially inline inner inout input ",
    "insensitive insert instead int integer intersect interval into invoker is isnull ",
    "isolation join json json_array json_arrayagg json_exists json_object json_objectagg ",
    "json_query json_scalar json_serialize json_table json_value keep key keys label language ",
    "large last lateral leading leakproof least left level like limit listen load local ",
    "localtime localtimestamp location lock locked logged lsn mapping match matched ",
    "materialized maxvalue merge merge_action method minute minvalue mode month move name ",
    "names national natural nchar nested new next nfc nfd nfkc nfkd no none normalize ",
    "normalized not nothing notify notnull nowait null nullif nulls numeric object objects of ",
    "off offset oids old omit on only operator option options or order ordinality others out ",
    "outer over overlaps overlay overriding owned owner parallel parameter parser partial ",
    "partition passing password path period placing plan plans policy position preceding ",
    "precision prepare prepared preserve primary prior privileges procedural procedure ",
    "procedures program publication quote quotes range read real reassign recursive ref ",
    "references referencing refresh reindex relative release rename repack repeatable replace ",
    "replica reset respect restart restrict return returning returns revoke right role ",
    "rollback rollup routine routines row rows rule savepoint scalar schema schemas scroll ",
    "search second security select sequence sequences serializable server session ",
    "session_user set setof sets share show similar simple skip smallint snapshot some source ",
    "sql stable standalone start statement statistics stdin stdout storage stored strict ",
    "string strip subscription substring support symmetric sysid system system_user table ",
    "tables tablesample tablespace target temp template temporary text then ties time ",
    "timestamp to trailing transaction transform treat trigger trim true truncate trusted ",
    "type types uescape unbounded uncommitted unconditional unencrypted union unique unknown ",
    "unlisten unlogged until update user using vacuum valid validate validator value values ",
    "varchar variadic varying verbose version view views virtual volatile wait when where ",
    "whitespace window with within without work wrapper write xml xmlattributes xmlconcat ",
    "xmlelement xmlexists xmlforest xmlnamespaces xmlparse xmlpi xmlroot xmlserialize ",
    "xmltable year yes zone",
);

/// Connect to the live server, or skip honestly when the environment does not
/// opt in or no server answers.
fn pg() -> Option<PgConnection> {
    if std::env::var(ENABLE_ENV).as_deref() != Ok("1") {
        eprintln!(
            "SKIP: live PostgreSQL check disabled; set {ENABLE_ENV}=1 with \
             OPUROM_TEST_PG_HOST/PORT/USER/DB pointing at a trust-auth server"
        );
        return None;
    }
    let host = std::env::var("OPUROM_TEST_PG_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("OPUROM_TEST_PG_PORT")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(5432);
    let user = std::env::var("OPUROM_TEST_PG_USER").unwrap_or_else(|_| "postgres".into());
    let database = std::env::var("OPUROM_TEST_PG_DB").unwrap_or_else(|_| "opurom_test".into());
    match PgConnection::connect(&host, port, &user, &database) {
        Ok(connection) => Some(connection),
        Err(error) => {
            eprintln!(
                "SKIP: cannot reach PostgreSQL at {host}:{port}/{database} ({error}); \
                 start a server with trust authentication to run this suite"
            );
            None
        }
    }
}

/// Lower one IR whose models stress identifier quoting: the reserved table
/// name `User`, reserved and non-reserved keyword columns, and one column
/// per word of the canonical keyword set.
fn keyword_ir() -> String {
    let mut fields =
        String::from(r#"{ "name": "id", "type": "int", "primary": true, "default": null }"#);
    let mut columns = 0;
    for word in KEYWORD_UNIVERSE.split_whitespace() {
        // Only plain identifiers can be emitted bare; anything else would be
        // a lexing question, not a keyword-quoting one.
        let mut chars = word.chars();
        let plain = chars
            .clone()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if !plain {
            continue;
        }
        fields.push_str(&format!(
            r#", {{ "name": "{word}", "type": "string", "primary": false, "default": null }}"#
        ));
        columns += 1;
    }
    assert_eq!(
        columns, 499,
        "universe must mirror the canonical keyword set"
    );
    format!(
        r##"{{
  "ir": "0.1.0",
  "app": "PgSchema",
  "state": [],
  "tree": {{ "id": 0, "kind": "Column", "props": {{}}, "children": [], "events": {{}} }},
  "theme": {{ "mode": "system", "accent": "#097FEB", "radius": 12 }},
  "models": [
    {{ "name": "User", "fields": [
      {{ "name": "id", "type": "int", "primary": true, "default": null }},
      {{ "name": "username", "type": "string", "primary": false, "default": null }},
      {{ "name": "password", "type": "string", "primary": false, "default": null }},
      {{ "name": "role", "type": "string", "primary": false, "default": "member" }},
      {{ "name": "order", "type": "string", "primary": false, "default": null }},
      {{ "name": "end", "type": "string", "primary": false, "default": null }}
    ] }},
    {{ "name": "Wordset", "fields": [{fields}] }}
  ],
  "api": [
    {{ "path": "/users", "model": "User", "handlers": ["list", "create"] }},
    {{ "path": "/users/:id", "model": "User", "handlers": ["get", "update", "delete"] }}
  ]
}}"##
    )
}

#[test]
fn generated_migrations_apply_to_live_postgres() {
    let Some(mut db) = pg() else {
        return;
    };

    let out = std::env::temp_dir().join(format!("opurom-serverc-pg-schema-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out);
    lower_service(&keyword_ir(), &out, &PathBuf::from("/tmp/dep-root")).expect("lowering works");

    let mut applied = Vec::new();
    let mut names: Vec<_> = fs::read_dir(out.join("migrations"))
        .expect("migrations dir")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with('0') && name.ends_with(".sql"))
        })
        .collect();
    names.sort();
    for path in &names {
        applied.push(fs::read_to_string(path).expect("migration readable"));
    }
    assert_eq!(applied.len(), 2, "both model migrations are generated");

    // Idempotent re-runs: start from a clean slate.
    db.exec("DROP TABLE IF EXISTS \"User\";")
        .expect("drop user table");
    db.exec("DROP TABLE IF EXISTS Wordset;")
        .expect("drop wordset table");

    // The whole point: every statement must parse against a real parser.
    for sql in &applied {
        db.exec(sql)
            .unwrap_or_else(|error| panic!("{sql}\n{error}"));
    }

    // Reserved identifiers stay usable after creation, and the plain table
    // name needs none.
    db.exec(
        "INSERT INTO \"User\" (id, username, \"order\", \"end\") \
             VALUES (1, 'ann', 'first', 'last');",
    )
    .expect("insert through quoted columns");
    let rows = db
        .query("SELECT username, \"order\" FROM \"User\" WHERE id = 1;")
        .expect("select through quoted columns");
    let row = rows.first().expect("one row");
    assert_eq!(
        row.get("username").and_then(|value| value.as_str()),
        Some("ann")
    );
    assert_eq!(
        row.get("order").and_then(|value| value.as_str()),
        Some("first")
    );
    db.query("SELECT id FROM Wordset LIMIT 1;")
        .expect("plain table name stays queryable");

    db.exec("DROP TABLE \"User\";").expect("cleanup user");
    db.exec("DROP TABLE Wordset;").expect("cleanup wordset");
    let _ = fs::remove_dir_all(&out);
}
