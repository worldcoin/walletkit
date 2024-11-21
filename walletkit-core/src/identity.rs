use semaphore::protocol::generate_nullifier_hash;

use crate::{proof::Context, u256::U256Wrapper};

#[derive(Clone, PartialEq, Eq, Debug, uniffi::Object)]
pub struct Identity(pub semaphore::identity::Identity);

impl From<Identity> for semaphore::identity::Identity {
    fn from(identity: Identity) -> Self {
        identity.0
    }
}

impl Identity {
    #[must_use]
    pub fn new(secret: &[u8]) -> Self {
        let mut secret_key = secret.to_vec();
        let identity = semaphore::identity::Identity::from_secret(&mut secret_key, None);
        Self(identity)
    }

    /// Generates a nullifier hash for a particular context (i.e. app + action) and the identity.
    /// The nullifier hash is a unique pseudo-random number for the particular identity and context.
    /// More information can be found [here](https://docs.world.org/world-id/concepts#vocabulary)
    ///
    /// [Protocol Reference](https://docs.semaphore.pse.dev/V2/technical-reference/circuits#nullifier-hash).
    #[must_use]
    pub fn generate_nullifier_hash(&self, context: &Context) -> U256Wrapper {
        generate_nullifier_hash(&self.0, context.external_nullifier).into()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test() {
        let identity = Identity::new(b"not_a_real_secret");
        let context = Context::new(b"app_id", b"action");
        let nullifier_hash = identity.generate_nullifier_hash(&context);
        println!("{}", nullifier_hash.to_hex_string());
    }
}
