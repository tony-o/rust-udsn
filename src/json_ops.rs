use std::fmt;

use serde::de::{Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};

use crate::DSN;

impl Serialize for DSN {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

struct DSNVisitor;
impl<'de> Visitor<'de> for DSNVisitor {
    type Value = DSN;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a dsn in the form of protocol://uri-or-path")
    }

    fn visit_str<E>(self, value: &str) -> Result<DSN, E>
    where
        E: serde::de::Error,
    {
        if let Some(dsn) = DSN::parse(value.to_owned().to_string()) {
            Ok(dsn)
        } else {
            Err(E::custom("failed to parse"))
        }
    }

    fn visit_string<E>(self, value: String) -> Result<DSN, E>
    where
        E: serde::de::Error,
    {
        if let Some(dsn) = DSN::parse(value.to_string()) {
            Ok(dsn)
        } else {
            Err(E::custom("failed to parse"))
        }
    }
}

impl<'de> Deserialize<'de> for DSN {
    fn deserialize<D>(deserializer: D) -> Result<DSN, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(DSNVisitor)
    }
}
