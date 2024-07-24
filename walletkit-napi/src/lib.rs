use walletkit::Hello;

#[macro_use]
extern crate napi_derive;

// best practice to wrap complex structs see: https://napi.rs/docs/concepts/class
#[napi(js_name = "Hello")]
pub struct JsHello {
  hello: Hello,
}

#[napi]
impl JsHello {
  #[napi(constructor)]
  pub fn new() -> Self {
    JsHello {
      hello: Hello::new(),
    }
  }
  #[napi]
  pub async fn echo(&self, query: String) -> String {
    self.hello.echo(query).await
  }

  #[napi]
  pub fn say_hello(&self) -> String {
    self.hello.say_hello().unwrap()
  }
}
