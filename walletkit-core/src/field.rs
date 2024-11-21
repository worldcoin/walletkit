#[derive(uniffi::Object, Debug, PartialEq, Eq, Clone)]
/// A field element in the Semaphore protocol.
pub struct Field(pub semaphore::Field);

impl Field {
    #[must_use]
    pub fn to_hex_string(&self) -> String {
        format!("{:#04x}", self.0)
    }
}

impl From<&Field> for semaphore::Field {
    fn from(val: &Field) -> Self {
        val.0
    }
}

impl From<Field> for semaphore::Field {
    fn from(val: Field) -> Self {
        val.0
    }
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex_string())
    }
}
