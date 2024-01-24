use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct Hello {}

#[uniffi::export]
impl Hello {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {})
    }
}
