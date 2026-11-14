//! Structured list query: `?limit=&offset=&sort=&order=&q=` with strict bounds,
//! a stable deterministic ordering and a `{items,total,count,limit,offset}`
//! response envelope over already-materialized JSON row objects.
//!
//! The layer is integer-only and std-only: it parses its own query string and
//! orders strings by bytes, so the same input always produces the same bytes.

use serde_json::{Map, Value};

/// Rows returned when `limit` is absent.
pub const DEFAULT_LIMIT: usize = 50;

/// Largest accepted page size; a larger `limit` is a 400.
pub const MAX_LIMIT: usize = 1000;

/// Largest accepted offset; a larger `offset` is a 400.
pub const MAX_OFFSET: usize = 1_000_000;

/// Admission bound on filter values and sort keys so a hostile query string
/// cannot force large allocations.
pub const MAX_PARAM_BYTES: usize = 256;

/// The validated parameters of a list request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListQuery {
    pub limit: usize,
    pub offset: usize,
    pub sort: Option<String>,
    pub descending: bool,
    pub filter: Option<String>,
}

/// Why a list query was rejected with 400.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryError(pub String);

impl QueryError {
    fn new(message: &str) -> QueryError {
        QueryError(message.to_string())
    }

    /// Canonical 400 response with the specific reason in the body.
    pub fn response(&self) -> crate::http::Response {
        crate::http::Response::error(400, &self.0)
    }
}

impl Default for ListQuery {
    fn default() -> ListQuery {
        ListQuery {
            limit: DEFAULT_LIMIT,
            offset: 0,
            sort: None,
            descending: false,
            filter: None,
        }
    }
}

impl ListQuery {
    /// Parse and validate a raw query string (the part after `?`).
    ///
    /// Unknown parameters are ignored so a link with a tracking query still
    /// lists. `limit`, `offset`, `sort`, `order` and `q` are strict: any value
    /// out of bounds or of the wrong type is a [`QueryError`].
    pub fn parse(raw: &str) -> Result<ListQuery, QueryError> {
        let mut query = ListQuery::default();
        for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = match pair.split_once('=') {
                Some((key, value)) => (key, value),
                None => (pair, ""),
            };
            let key = decode(key);
            let value = decode(value);
            match key.as_str() {
                "limit" => query.limit = parse_integer(&value, "limit", MAX_LIMIT)?,
                "offset" => query.offset = parse_integer(&value, "offset", MAX_OFFSET)?,
                "sort" => {
                    if value.len() > MAX_PARAM_BYTES {
                        return Err(QueryError::new("invalid_sort"));
                    }
                    query.sort = Some(value);
                }
                "order" => {
                    query.descending = match value.as_str() {
                        "asc" => false,
                        "desc" => true,
                        _ => return Err(QueryError::new("invalid_order")),
                    }
                }
                "q" => {
                    if value.len() > MAX_PARAM_BYTES {
                        return Err(QueryError::new("invalid_q"));
                    }
                    query.filter = Some(value);
                }
                _ => {}
            }
        }
        Ok(query)
    }

    /// Apply the filter, sort, and page to `rows`, returning the response
    /// envelope. Ordering is stable: rows that compare equal on the sort key
    /// keep their incoming order, and a missing or non-scalar key sorts last.
    /// The fields are `items` (the page), `total` (rows before paging),
    /// `count` (rows in this page), `limit` and `offset`. Object keys are
    /// sorted, so the serialized bytes are deterministic.
    pub fn apply(&self, rows: Vec<Value>) -> Value {
        let mut rows: Vec<Value> = match self.filter.as_deref() {
            Some(filter) if !filter.is_empty() => {
                let needle = filter.to_ascii_lowercase();
                rows.into_iter()
                    .filter(|row| row_contains(row, &needle))
                    .collect()
            }
            _ => rows,
        };
        if let Some(sort) = self.sort.as_deref() {
            if !sort.is_empty() {
                rows.sort_by(|left, right| {
                    let ordering = compare_keys(left.get(sort), right.get(sort));
                    if self.descending {
                        ordering.reverse()
                    } else {
                        ordering
                    }
                });
            }
        }
        let total = rows.len();
        let start = self.offset.min(total);
        let end = start.saturating_add(self.limit).min(total);
        let items: Vec<Value> = rows.drain(start..end).collect();
        let count = items.len();
        let mut envelope = Map::new();
        envelope.insert("items".to_string(), Value::Array(items));
        envelope.insert("total".to_string(), Value::from(total as u64));
        envelope.insert("count".to_string(), Value::from(count as u64));
        envelope.insert("limit".to_string(), Value::from(self.limit as u64));
        envelope.insert("offset".to_string(), Value::from(self.offset as u64));
        Value::Object(envelope)
    }
}

/// Parse a bounded non-negative integer. Negative, non-integer and over-cap
/// values are all rejected with a parameter-specific 400 reason.
fn parse_integer(raw: &str, name: &str, maximum: usize) -> Result<usize, QueryError> {
    if raw.is_empty() {
        return Err(QueryError::new(&format!("invalid_{}", name)));
    }
    let value = if raw.bytes().all(|byte| byte.is_ascii_digit()) {
        raw.parse::<u64>()
            .map_err(|_| QueryError::new(&format!("invalid_{}", name)))?
    } else if raw.starts_with('-') && raw[1..].bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(QueryError::new(&format!("negative_{}", name)));
    } else {
        return Err(QueryError::new(&format!("invalid_{}", name)));
    };
    if value > maximum as u64 {
        return Err(QueryError::new(&format!("{}_too_large", name)));
    }
    Ok(value as usize)
}

/// Byte-ordered comparison of two optional JSON values. Sort keys order by
/// type (numbers, then strings, then booleans) and a missing or null key sorts
/// after every present scalar so it is deterministic.
fn compare_keys(left: Option<&Value>, right: Option<&Value>) -> std::cmp::Ordering {
    let rank = |value: Option<&Value>| match value {
        Some(Value::Number(_)) => 0u8,
        Some(Value::String(_)) => 1,
        Some(Value::Bool(_)) => 2,
        _ => 3,
    };
    let (left_rank, right_rank) = (rank(left), rank(right));
    if left_rank != right_rank {
        return left_rank.cmp(&right_rank);
    }
    match (left, right) {
        (Some(Value::Number(a)), Some(Value::Number(b))) => compare_numbers(a, b),
        (Some(Value::String(a)), Some(Value::String(b))) => a.as_bytes().cmp(b.as_bytes()),
        (Some(Value::Bool(a)), Some(Value::Bool(b))) => a.cmp(b),
        _ => std::cmp::Ordering::Equal,
    }
}

/// Compare two JSON numbers exactly: integers first by integer value, then a
/// mixture of integers and floats through their `f64` value.
fn compare_numbers(a: &serde_json::Number, b: &serde_json::Number) -> std::cmp::Ordering {
    match (a.as_i64(), b.as_i64()) {
        (Some(a), Some(b)) => a.cmp(&b),
        _ => {
            let (a, b) = (a.as_f64().unwrap_or(0.0), b.as_f64().unwrap_or(0.0));
            a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal)
        }
    }
}

/// True when any value of `filter` matches `needle` exactly or contains it as a
/// case-insensitive substring.
fn row_contains(row: &Value, needle: &str) -> bool {
    match row {
        Value::Object(object) => object.values().any(|value| value_matches(value, needle)),
        other => value_matches(other, needle),
    }
}

fn value_matches(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(text) => text.to_ascii_lowercase().contains(needle),
        Value::Number(number) => number.to_string().contains(needle),
        Value::Bool(flag) => flag.to_string().contains(needle),
        Value::Null => false,
        _ => false,
    }
}

/// Percent-decode a query component, treating `+` as a space. Invalid escapes
/// are kept verbatim, matching the path decoder.
fn decode(raw: &str) -> String {
    let replaced = raw.replace('+', " ");
    crate::http::percent_decode(&replaced)
}
