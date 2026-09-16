use serde_json::{Map, Number, Value};

use crate::error::{ProblemCode, RelayError};

/// RFC 8785 JSON Canonicalization for the flat objects used by web-login v1.
pub fn canonicalize(value: &Value) -> Result<String, RelayError> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

pub fn canonicalize_object(fields: &[(&str, Value)]) -> Result<String, RelayError> {
    let mut map = Map::new();
    for (key, value) in fields {
        if map.insert((*key).to_string(), value.clone()).is_some() {
            return Err(RelayError::problem(ProblemCode::InvalidRequest));
        }
    }
    canonicalize(&Value::Object(map))
}

fn write_value(out: &mut String, value: &Value) -> Result<(), RelayError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(out, n)?,
        Value::String(s) => out.push_str(&serde_json::to_string(s).map_err(|_| {
            RelayError::problem(ProblemCode::InvalidRequest)
        })?),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(*key).map_err(|_| {
                    RelayError::problem(ProblemCode::InvalidRequest)
                })?);
                out.push(':');
                write_value(out, &map[*key])?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_number(out: &mut String, n: &Number) -> Result<(), RelayError> {
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
        return Ok(());
    }
    Err(RelayError::problem(ProblemCode::InvalidRequest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn android_key_sort_vector() {
        let value = json!({"z": 1, "a": "first"});
        assert_eq!(canonicalize(&value).unwrap(), r#"{"a":"first","z":1}"#);
    }

    #[test]
    fn qr_object_lexicographic_order() {
        let canonical = canonicalize_object(&[
            ("domain", json!("login.example.org")),
            ("exp", json!(1800000300000_i64)),
            ("iat", json!(1800000000000_i64)),
            ("nonce", json!("nonce_12345678901")),
            ("session", json!("session_123456789")),
            ("v", json!(1)),
        ])
        .unwrap();
        assert_eq!(
            canonical,
            r#"{"domain":"login.example.org","exp":1800000300000,"iat":1800000000000,"nonce":"nonce_12345678901","session":"session_123456789","v":1}"#
        );
    }

    #[test]
    fn rejects_floats() {
        let value = json!({"n": 1.5});
        assert!(canonicalize(&value).is_err());
    }
}
