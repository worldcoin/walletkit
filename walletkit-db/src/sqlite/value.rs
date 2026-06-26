//! Parameter and column value types for the safe `SQLite` wrapper.

/// A value that can be bound to a prepared statement parameter or read from
/// a result column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// 64-bit signed integer.
    Integer(i64),
    /// Binary blob.
    Blob(Vec<u8>),
    /// UTF-8 text.
    Text(String),
    /// SQL NULL.
    Null,
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Self::Integer(v)
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Self::Blob(v)
    }
}

impl From<&[u8]> for Value {
    fn from(v: &[u8]) -> Self {
        Self::Blob(v.to_vec())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Self::Text(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Self::Text(v.to_string())
    }
}

/// Convenience macro for building parameter lists.
///
/// Usage: `params![1_i64, blob.as_slice(), "text"]`
#[macro_export]
macro_rules! params {
    ($($val:expr),* $(,)?) => {
        &[$($crate::Value::from($val)),*][..]
    };
}
