/// Several types will serialize to and from strings, e.g.,
/// as UUIDs or base64. This macro implements those in terms
/// of `to_string` and `parse`, a.k.a., [`std::fmt::Display`]
/// and [`std::str::FromStr`].
macro_rules! impl_to_from_sql_and_serde {
    ($ty:ident) => {
        impl rusqlite::ToSql for $ty {
            fn to_sql(&self) -> Result<rusqlite::types::ToSqlOutput<'_>, rusqlite::Error> {
                Ok(rusqlite::types::ToSqlOutput::Owned(self.to_string().into()))
            }
        }

        impl rusqlite::types::FromSql for $ty {
            fn column_result(
                value: rusqlite::types::ValueRef<'_>,
            ) -> Result<Self, rusqlite::types::FromSqlError> {
                let string = <String>::column_result(value)?;
                string.parse().map_err(rusqlite::types::FromSqlError::other)
            }
        }

        impl serde::Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}
