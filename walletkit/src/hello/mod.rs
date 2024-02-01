use crate::WalletKitResult;

pub struct Hello {}

impl Hello {
    pub fn new() -> Self {
        Self {}
    }
}

impl Hello {
    pub fn echo(&self, input: String) -> String {
        input
    }
    pub fn say_hello(&self) -> WalletKitResult<String> {
        Ok("Hello, World!".to_string())
    }
}
