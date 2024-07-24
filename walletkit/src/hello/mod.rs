use crate::WalletKitResult;

pub struct Hello {}

impl Hello {
    pub fn new() -> Self {
        Self {}
    }
}

impl Hello {
    pub async fn echo(&self, input: String) -> String {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        input
    }
    pub fn say_hello(&self) -> WalletKitResult<String> {
        Ok("Hello, World!".to_string())
    }
}
