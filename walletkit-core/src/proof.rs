use ruint::aliases::U256;
use semaphore::hash_to_field;

pub struct Context {
    pub external_nullifier: U256,
}

impl Context {
    #[must_use]
    pub fn new(app_id: &[u8], _action: &[u8]) -> Self {
        let external_nullifier = hash_to_field(app_id);
        // TODO: handle action properly
        Self { external_nullifier }
    }
}
