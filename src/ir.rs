//! Full-stack IR v0.1 data model: state, tree, theme, models and api routes.
//!
//! The IR is parsed with `serde_json` value access only, so the crate needs no
//! derive feature and stays buildable with a single cached dependency.

use serde_json::Value;

/// The only IR version accepted by this runtime.
pub const IR_VERSION: &str = "0.1";

/// Column type of a model field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldType {
    Int,
    Text,
    Bool,
}

impl FieldType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FieldType::Int => "int",
            FieldType::Text => "string",
            FieldType::Bool => "bool",
        }
    }

    /// SQL column type used by the generated migrations.
    pub fn sql_type(&self) -> &'static str {
        match self {
            FieldType::Int => "INTEGER",
            FieldType::Text => "TEXT",
            FieldType::Bool => "INTEGER",
        }
    }

    pub fn parse(raw: &str) -> Option<FieldType> {
        match raw {
            "int" => Some(FieldType::Int),
            "string" => Some(FieldType::Text),
            "bool" => Some(FieldType::Bool),
            _ => None,
        }
    }
}

/// One model field.
#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub ty: FieldType,
    pub primary: bool,
    pub default: Option<Value>,
}

/// One data model.
#[derive(Clone, Debug)]
pub struct Model {
    pub name: String,
    pub fields: Vec<Field>,
}

impl Model {
    /// The single primary field, if the model declares one.
    pub fn primary(&self) -> Option<&Field> {
        self.fields.iter().find(|field| field.primary)
    }

    /// SQL table name. Matches `opurom-db`, which uses the model name as-is.
    pub fn table(&self) -> String {
        self.name.clone()
    }
}

/// One `api` block: a path, the model it serves and the handler verbs.
#[derive(Clone, Debug)]
pub struct Api {
    pub path: String,
    pub model: String,
    pub handlers: Vec<String>,
}

/// One declared state variable.
#[derive(Clone, Debug)]
pub struct StateVar {
    pub name: String,
    pub ty: String,
    pub init: Value,
}

/// Theme tokens used by the SSR host.
#[derive(Clone, Debug)]
pub struct Theme {
    pub mode: String,
    pub accent: String,
    pub radius: f64,
    pub tokens: Vec<(String, String)>,
}

impl Default for Theme {
    fn default() -> Self {
        Theme {
            mode: "system".to_string(),
            accent: "#097FEB".to_string(),
            radius: 12.0,
            tokens: Vec::new(),
        }
    }
}

impl Theme {
    /// Parse a theme object. Unknown keys are ignored (forward compatibility).
    pub fn from_json(value: &Value) -> Option<Theme> {
        let object = value.as_object()?;
        let mut theme = Theme::default();
        if let Some(mode) = object.get("mode").and_then(Value::as_str) {
            theme.mode = mode.to_string();
        }
        if let Some(accent) = object.get("accent").and_then(Value::as_str) {
            theme.accent = accent.to_string();
        }
        if let Some(radius) = object.get("radius").and_then(Value::as_f64) {
            theme.radius = radius;
        }
        if let Some(tokens) = object.get("tokens").and_then(Value::as_object) {
            for (key, value) in tokens {
                if let Some(text) = value.as_str() {
                    theme.tokens.push((key.clone(), text.to_string()));
                }
            }
        }
        Some(theme)
    }
}

/// The parsed full-stack IR.
#[derive(Clone, Debug)]
pub struct Ir {
    pub ir: String,
    pub app: String,
    pub state: Vec<StateVar>,
    pub tree: Option<Value>,
    pub theme: Theme,
    pub models: Vec<Model>,
    pub api: Vec<Api>,
}

impl Ir {
    /// Parse a full-stack IR document. The error string is a readable
    /// diagnostic; no panic is ever raised.
    pub fn parse(text: &str) -> Result<Ir, String> {
        let root: Value =
            serde_json::from_str(text).map_err(|err| format!("invalid IR JSON: {}", err))?;
        let version = root
            .get("ir")
            .and_then(Value::as_str)
            .ok_or_else(|| "invalid IR: missing \"ir\" version".to_string())?;
        if version != IR_VERSION {
            return Err(format!(
                "invalid IR: expected ir \"{}\", found \"{}\"",
                IR_VERSION, version
            ));
        }
        let app = root
            .get("app")
            .and_then(Value::as_str)
            .unwrap_or("opurom")
            .to_string();

        let mut state = Vec::new();
        if let Some(items) = root.get("state").and_then(Value::as_array) {
            for item in items {
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "invalid IR: state entry without name".to_string())?;
                state.push(StateVar {
                    name: name.to_string(),
                    ty: item
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("string")
                        .to_string(),
                    init: item.get("init").cloned().unwrap_or(Value::Null),
                });
            }
        }

        let tree = root.get("tree").cloned();
        let theme = root
            .get("theme")
            .and_then(Theme::from_json)
            .unwrap_or_default();

        let mut models = Vec::new();
        if let Some(items) = root.get("models").and_then(Value::as_array) {
            for item in items {
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "invalid IR: model without name".to_string())?;
                let mut fields = Vec::new();
                if let Some(raw_fields) = item.get("fields").and_then(Value::as_array) {
                    for raw_field in raw_fields {
                        let field_name =
                            raw_field
                                .get("name")
                                .and_then(Value::as_str)
                                .ok_or_else(|| {
                                    format!("invalid IR: model {} field without name", name)
                                })?;
                        let ty_name =
                            raw_field
                                .get("type")
                                .and_then(Value::as_str)
                                .ok_or_else(|| {
                                    format!(
                                        "invalid IR: model {} field {} without type",
                                        name, field_name
                                    )
                                })?;
                        let ty = FieldType::parse(ty_name).ok_or_else(|| {
                            format!(
                                "invalid IR: model {} field {} has unknown type \"{}\"",
                                name, field_name, ty_name
                            )
                        })?;
                        fields.push(Field {
                            name: field_name.to_string(),
                            ty,
                            primary: raw_field
                                .get("primary")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            default: raw_field.get("default").cloned(),
                        });
                    }
                }
                models.push(Model {
                    name: name.to_string(),
                    fields,
                });
            }
        }

        let mut api = Vec::new();
        if let Some(items) = root.get("api").and_then(Value::as_array) {
            for item in items {
                let path = item
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "invalid IR: api entry without path".to_string())?;
                let model = item
                    .get("model")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("invalid IR: api {} without model", path))?
                    .to_string();
                let handlers = item
                    .get("handlers")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                api.push(Api {
                    path: path.to_string(),
                    model,
                    handlers,
                });
            }
        }

        Ok(Ir {
            ir: version.to_string(),
            app,
            state,
            tree,
            theme,
            models,
            api,
        })
    }

    /// Look up a model by name.
    pub fn model(&self, name: &str) -> Option<&Model> {
        self.models.iter().find(|model| model.name == name)
    }
}
