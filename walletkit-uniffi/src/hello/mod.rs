use std::sync::{Arc, RwLock};

#[derive(uniffi::Object)]
pub struct Hello(RwLock<walletkit::Hello>);

#[uniffi::export]
impl Hello {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self(RwLock::new(walletkit::Hello::new())))
    }
}
