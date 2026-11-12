//! Server-side rendering host.
//!
//! The renderer walks the same IR tree the client uses and emits deterministic
//! HTML bytes: the same IR and the same theme always produce identical output.
//! State interpolation (`{name}`) is resolved against the IR's initial state.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::Value;

use crate::ir::{Ir, Theme};

/// Escape text for HTML body content.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Render the IR tree to a deterministic HTML page.
///
/// `theme_json` is a JSON object (`{"mode":"dark","accent":"#FF4D6D","radius":8}`)
/// that overrides the IR's own theme; pass an empty string to use the IR theme.
/// The same IR and theme always produce byte-identical output.
pub fn ssr_html(ir_json: &str, theme_json: &str) -> String {
    match try_ssr_html(ir_json, theme_json) {
        Ok(html) => html,
        Err(message) => format!(
            "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>SSR error</title></head>\n<body><main id=\"app\" data-error=\"{}\">{}</main></body>\n</html>\n",
            escape_html(&message),
            escape_html(&message)
        ),
    }
}

/// Fallible variant of [`ssr_html`].
pub fn try_ssr_html(ir_json: &str, theme_json: &str) -> Result<String, String> {
    let ir = Ir::parse(ir_json)?;
    let theme = resolve_theme(&ir.theme, theme_json)?;
    Ok(render(&ir, &theme))
}

/// Merge an optional theme override on top of the IR theme.
fn resolve_theme(base: &Theme, theme_json: &str) -> Result<Theme, String> {
    if theme_json.trim().is_empty() {
        return Ok(base.clone());
    }
    let value: Value =
        serde_json::from_str(theme_json).map_err(|err| format!("invalid theme JSON: {}", err))?;
    let mut theme = base.clone();
    if let Some(object) = value.as_object() {
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
            theme.tokens.clear();
            for (key, value) in tokens {
                if let Some(text) = value.as_str() {
                    theme.tokens.push((key.clone(), text.to_string()));
                }
            }
        }
    }
    Ok(theme)
}

/// Render an already-parsed IR with an explicit theme.
pub fn render(ir: &Ir, theme: &Theme) -> String {
    let state: BTreeMap<String, Value> = ir
        .state
        .iter()
        .map(|var| (var.name.clone(), var.init.clone()))
        .collect();

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\" data-theme=\"");
    html.push_str(&escape_html(&theme.mode));
    html.push_str("\">\n<head>\n<meta charset=\"utf-8\">\n<title>");
    html.push_str(&escape_html(&ir.app));
    html.push_str("</title>\n<style>\n");
    write!(
        html,
        ":root {{ --accent: {}; --radius: {}px; }}\n",
        theme.accent,
        radius_px(theme.radius)
    )
    .ok();
    for (key, value) in &theme.tokens {
        write!(html, ":root {{ --{}: {}; }}\n", key, value).ok();
    }
    html.push_str(
        "body { margin: 0; font-family: system-ui, sans-serif; background: var(--surface, #FFFFFF); color: var(--onSurface, #101828); }\n\
         .column { display: flex; flex-direction: column; }\n\
         .row { display: flex; flex-direction: row; }\n\
         .button { border: 1px solid var(--accent); background: var(--accent); color: #FFFFFF; border-radius: var(--radius); cursor: pointer; }\n\
         .text { white-space: pre-wrap; }\n",
    );
    html.push_str("</style>\n</head>\n<body>\n");
    write!(
        html,
        "<main id=\"app\" data-app=\"{}\">\n",
        escape_html(&ir.app)
    )
    .ok();
    if let Some(tree) = &ir.tree {
        render_node(tree, &state, theme, &mut html, 1);
    }
    html.push_str("</main>\n</body>\n</html>\n");
    html
}

/// Round a radius to a stable integer number of pixels.
fn radius_px(radius: f64) -> i64 {
    radius.round() as i64
}

/// Render one IR node and its subtree.
fn render_node(
    node: &Value,
    state: &BTreeMap<String, Value>,
    theme: &Theme,
    html: &mut String,
    depth: usize,
) {
    let kind = node
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("Container");
    let props = node.get("props").and_then(Value::as_object);
    let children = node
        .get("children")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let tag = tag_for(kind);
    let class = class_for(kind);
    let indent = "  ".repeat(depth);

    html.push_str(&indent);
    html.push('<');
    html.push_str(tag);
    html.push_str(" class=\"");
    html.push_str(class);
    html.push('"');
    let style = inline_style(props, theme);
    if !style.is_empty() {
        html.push_str(" style=\"");
        html.push_str(&style);
        html.push('"');
    }
    if let Some(label) = props.and_then(|p| p.get("label")).and_then(Value::as_str) {
        html.push_str(" data-label=\"");
        html.push_str(&escape_html(&resolve(label, state)));
        html.push('"');
    }
    html.push('>');

    let text = node_text(kind, props, state);
    if !text.is_empty() {
        html.push_str(&escape_html(&text));
    }
    if children.is_empty() {
        html.push_str("</");
        html.push_str(tag);
        html.push_str(">\n");
        return;
    }
    html.push('\n');
    for child in &children {
        render_node(child, state, theme, html, depth + 1);
    }
    html.push_str(&indent);
    html.push_str("</");
    html.push_str(tag);
    html.push_str(">\n");
}

/// HTML tag used for an IR kind.
fn tag_for(kind: &str) -> &'static str {
    match kind {
        "Text" => "span",
        "Button" => "button",
        "Input" => "input",
        "Image" => "img",
        "Divider" => "hr",
        _ => "div",
    }
}

/// CSS class used for an IR kind.
fn class_for(kind: &str) -> &'static str {
    match kind {
        "Column" => "column",
        "Row" => "row",
        "Text" => "text",
        "Button" => "button",
        "Input" => "input",
        "Image" => "image",
        "Card" => "card",
        "Divider" => "divider",
        "Icon" => "icon",
        "Badge" => "badge",
        "Progress" => "progress",
        "Switch" => "switch",
        "Slider" => "slider",
        "Checkbox" => "checkbox",
        "Radio" => "radio",
        "Dialog" => "dialog",
        "Tabs" => "tabs",
        "List" => "list",
        "Grid" => "grid",
        "Scroll" => "scroll",
        "Avatar" => "avatar",
        "Spinner" => "spinner",
        "Spacer" => "spacer",
        _ => "container",
    }
}

/// The text content of a node, with state interpolation resolved.
fn node_text(
    kind: &str,
    props: Option<&serde_json::Map<String, Value>>,
    state: &BTreeMap<String, Value>,
) -> String {
    let props = match props {
        Some(props) => props,
        None => return String::new(),
    };
    let raw = match kind {
        "Text" => props.get("value").and_then(Value::as_str),
        "Button" | "Badge" | "Avatar" => props.get("label").and_then(Value::as_str),
        "Icon" => props.get("name").and_then(Value::as_str),
        "Dialog" => props.get("title").and_then(Value::as_str),
        _ => None,
    };
    match raw {
        Some(text) => resolve(text, state),
        None => String::new(),
    }
}

/// Resolve `{name}` placeholders against the state map.
fn resolve(text: &str, state: &BTreeMap<String, Value>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) => {
                let name = &after[..end];
                match state.get(name) {
                    Some(value) => out.push_str(&value_to_string(value)),
                    None => {
                        out.push('{');
                        out.push_str(name);
                        out.push('}');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Render a state value as a plain string.
fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Inline CSS derived from the canonical style props and the theme tokens.
fn inline_style(props: Option<&serde_json::Map<String, Value>>, theme: &Theme) -> String {
    let props = match props {
        Some(props) => props,
        None => return String::new(),
    };
    let mut style = String::new();
    if let Some(value) = props.get("padding").and_then(Value::as_f64) {
        write!(style, "padding: {}px; ", value.round() as i64).ok();
    }
    if let Some(value) = props.get("margin").and_then(Value::as_f64) {
        write!(style, "margin: {}px; ", value.round() as i64).ok();
    }
    if let Some(value) = props.get("gap").and_then(Value::as_f64) {
        write!(style, "gap: {}px; ", value.round() as i64).ok();
    }
    if let Some(value) = props.get("color").and_then(Value::as_str) {
        write!(style, "background: {}; ", value).ok();
    }
    if let Some(value) = props.get("radius").and_then(Value::as_f64) {
        write!(style, "border-radius: {}px; ", value.round() as i64).ok();
    } else {
        write!(style, "border-radius: {}px; ", radius_px(theme.radius)).ok();
    }
    if let Some(value) = props.get("opacity").and_then(Value::as_f64) {
        write!(style, "opacity: {}; ", value).ok();
    }
    if let Some(value) = props.get("border").and_then(Value::as_str) {
        write!(style, "border: 1px solid {}; ", value).ok();
    }
    if let Some(value) = props.get("shadow").and_then(Value::as_f64) {
        write!(
            style,
            "box-shadow: 0 {}px {}px rgba(0,0,0,0.2); ",
            value.round() as i64,
            value.round() as i64
        )
        .ok();
    }
    if let Some(value) = props.get("gradient").and_then(Value::as_str) {
        write!(style, "background: linear-gradient(90deg, {}); ", value).ok();
    }
    if let Some(value) = props.get("size").and_then(Value::as_f64) {
        write!(style, "font-size: {}px; ", value.round() as i64).ok();
    }
    if let Some(value) = props.get("align").and_then(Value::as_str) {
        write!(style, "align-items: {}; ", value).ok();
    }
    style.trim_end().to_string()
}
