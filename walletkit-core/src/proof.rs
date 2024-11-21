use ruint::aliases::U256;
use semaphore::hash_to_field;

#[derive(Clone, PartialEq, Eq, Debug, uniffi::Object)]
pub struct Context {
    pub external_nullifier: U256,
}

#[uniffi::export]
impl Context {
    #[must_use]
    #[uniffi::constructor]
    pub fn new(app_id: &[u8], action: &[u8]) -> Self {
        let external_nullifier = hash_to_field(app_id);
        dbg!(&action);
        // TODO: handle action properly
        Self { external_nullifier }
    }
}
