//! SSR determinism and IR parsing tests.

use opurom_server::ir::Ir;
use opurom_server::ssr::ssr_html;

const IR: &str = r##"{
  "ir": "0.1",
  "app": "Counter",
  "state": [ { "name": "count", "type": "int", "init": 7 } ],
  "tree": {
    "id": 0,
    "kind": "Column",
    "props": { "gap": 8, "padding": 16, "align": "center" },
    "children": [
      {
        "id": 1,
        "kind": "Text",
        "props": { "value": "Count: {count}", "size": 24 },
        "children": [],
        "events": {}
      },
      {
        "id": 2,
        "kind": "Row",
        "props": { "gap": 8 },
        "children": [
          {
            "id": 3,
            "kind": "Button",
            "props": { "label": "+" },
            "children": [],
            "events": { "tap": { "op": "add", "target": "count", "value": 1 } }
          }
        ],
        "events": {}
      }
    ],
    "events": {}
  },
  "theme": { "mode": "system", "accent": "#4F46E5", "radius": 12 }
}"##;

#[test]
fn same_ir_and_theme_produce_identical_bytes() {
    let first = ssr_html(IR, "");
    let second = ssr_html(IR, "");
    assert_eq!(first, second);
    assert!(!first.is_empty());
}

#[test]
fn theme_changes_the_output() {
    let base = ssr_html(IR, "");
    let dark = ssr_html(
        IR,
        "{\"mode\":\"dark\",\"accent\":\"#FF4D6D\",\"radius\":4}",
    );
    assert_ne!(base, dark);
    assert!(dark.contains("#FF4D6D"), "{}", dark);
    assert!(dark.contains("--radius: 4px"), "{}", dark);
    assert!(base.contains("#4F46E5"), "{}", base);
}

#[test]
fn state_interpolation_is_resolved() {
    let html = ssr_html(IR, "");
    assert!(html.contains("Count: 7"), "{}", html);
    assert!(!html.contains("{count}"), "{}", html);
}

#[test]
fn kinds_map_to_html_elements() {
    let html = ssr_html(IR, "");
    assert!(html.contains("<div class=\"column\""), "{}", html);
    assert!(html.contains("<span class=\"text\""), "{}", html);
    assert!(html.contains("<button class=\"button\""), "{}", html);
    assert!(html.contains("<title>Counter</title>"), "{}", html);
}

#[test]
fn ir_rejects_a_wrong_version() {
    let broken = IR.replace("\"ir\": \"0.1\"", "\"ir\": \"0.2\"");
    let error = Ir::parse(&broken).expect_err("version 0.2 is rejected");
    assert!(error.contains("0.1"), "{}", error);
}

#[test]
fn ir_parses_models_and_api() {
    let full = r##"{
      "ir": "0.1",
      "app": "TodoApp",
      "models": [
        { "name": "Todo", "fields": [
          { "name": "id", "type": "int", "primary": true, "default": null },
          { "name": "done", "type": "bool", "primary": false, "default": false }
        ] }
      ],
      "api": [ { "path": "/todos", "model": "Todo", "handlers": ["list", "create"] } ]
    }"##;
    let ir = Ir::parse(full).expect("full-stack IR parses");
    assert_eq!(ir.app, "TodoApp");
    assert_eq!(ir.models.len(), 1);
    assert_eq!(ir.models[0].fields.len(), 2);
    assert_eq!(ir.api.len(), 1);
    assert_eq!(ir.api[0].handlers, vec!["list", "create"]);
}
