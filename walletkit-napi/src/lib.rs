#[macro_use]
extern crate napi_derive;

#[napi]
pub struct Hello(walletkit::Hello);
