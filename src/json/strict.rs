use std::collections::HashSet;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;

use crate::error::{ProblemCode, RelayError};

pub fn from_slice<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, RelayError> {
    let text = std::str::from_utf8(bytes).map_err(|_| RelayError::problem(ProblemCode::InvalidRequest))?;
    from_str(text)
}

pub fn from_str<T: for<'de> Deserialize<'de>>(text: &str) -> Result<T, RelayError> {
    let mut de = serde_json::Deserializer::from_str(text);
    let value = StrictValue
        .deserialize(&mut de)
        .map_err(|_| RelayError::problem(ProblemCode::InvalidRequest))?;
    de.end()
        .map_err(|_| RelayError::problem(ProblemCode::InvalidRequest))?;
    serde_json::from_value(value).map_err(|_| RelayError::problem(ProblemCode::InvalidRequest))
}

struct StrictValue;

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a strict JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        if v > i64::MAX as u64 {
            return Err(E::custom("integer overflow"));
        }
        Ok(Value::from(v as i64))
    }

    fn visit_f64<E: de::Error>(self, _v: f64) -> Result<Self::Value, E> {
        Err(E::custom("floating-point numbers are not allowed"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(Value::String(v.to_string()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(Value::String(v))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(StrictValue)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = HashSet::new();
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let value = map.next_value_seed(StrictValue)?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Sample {
        a: i64,
        b: String,
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert!(from_str::<Sample>(r#"{"a":1,"a":2,"b":"x"}"#).is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_floats() {
        assert!(from_str::<Sample>(r#"{"a":1,"b":"x","c":true}"#).is_err());
        assert!(from_str::<Sample>(r#"{"a":1.5,"b":"x"}"#).is_err());
    }

    #[test]
    fn accepts_exact_object() {
        let parsed = from_str::<Sample>(r#"{"a":1,"b":"x"}"#).unwrap();
        assert_eq!(parsed, Sample { a: 1, b: "x".into() });
    }
}
