//! `#[js_type]` for the `walletkit-web` facade.
//!
//! Records and enums cross the worker boundary as plain structured-clone data, so
//! each one needs a TypeScript declaration and conversions to and from `JsValue`.
//! `#[js_type]` derives all three from one Rust declaration, so they cannot drift
//! apart.
//!
//! ```ignore
//! /// Stored credential metadata.
//! #[js_type(remote = storage::CredentialRecord, output)]
//! struct CredentialRecord {
//!     credential_id: u64,
//!     is_expired: bool,
//! }
//! ```
//!
//! # Container options
//!
//! - `input` / `output`: generate `FromJs` / `ToJs`. At least one is required.
//! - `remote = path`: describe a type from another crate instead of defining one.
//!   The declaration is a schema: its fields must list every field of the remote
//!   type, and each declared field type is checked against the remote field's type
//!   through `JsSchema`. A unit struct of the declared name stands in for the remote
//!   type in other schemas.
//! - `tag = "name"`: an enum becomes a union of objects with a `name` property naming
//!   the variant. Without it, an enum must have only unit variants and becomes a
//!   union of strings.
//! - `rename_all = "snake_case" | "lowercase"`: how variant names are spelled in
//!   JavaScript. Defaults to `snake_case`. Fields are always `camelCase`.
//! - `readonly`: mark every property and array as `readonly` in TypeScript.
//!
//! # Field and variant options, in `#[js(...)]`
//!
//! - `rename = "name"`: the JavaScript name of a field or variant.
//! - `ts = "type"`: the TypeScript type, instead of the one derived from the Rust type.
//! - `to_js = path` / `from_js = path`: convert the field with
//!   `fn(&T) -> Result<JsValue, JsValue>` / `fn(&JsValue, &str) -> Result<T, JsValue>`
//!   instead of `ToJs` / `FromJs`. The schema check is skipped for that direction.
//! - `flatten`: merge the fields of an output-only record or tagged enum into the
//!   containing object.
//!
//! The generated code refers to `crate::js`, so the macro only works inside
//! `walletkit-web`.

mod convert;
mod model;
mod ts;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};

/// Derives a TypeScript declaration and `JsValue` conversions. See the crate docs.
#[proc_macro_attribute]
pub fn js_type(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand(attr: TokenStream2, item: TokenStream2) -> syn::Result<TokenStream2> {
    let mut item: syn::DeriveInput = syn::parse2(item)?;
    let model = model::JsType::parse(attr, &item)?;
    model::strip_js_attributes(&mut item);

    let declaration = if model.remote.is_some() {
        let syn::DeriveInput { attrs, ident, .. } = &item;
        let docs = attrs.iter().filter(|attr| attr.path().is_ident("doc"));
        // Public because it is the associated type of a public trait implementation.
        quote! {
            #(#docs)*
            #[allow(dead_code, reason = "names the remote type in other schemas")]
            pub struct #ident;
        }
    } else {
        quote!(#item)
    };
    let target = model.target();
    let schema = &model.ident;
    let typescript = ts::render(&model)?;
    let typescript_const = format_ident!(
        "TS_{}",
        heck::AsShoutySnakeCase(schema.to_string()).to_string()
    );
    let to_js = model.output.then(|| convert::to_js(&model));
    let from_js = model.input.then(|| convert::from_js(&model));

    Ok(quote! {
        #declaration

        impl crate::js::JsSchema for #target {
            type Schema = #schema;
        }

        #[::wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
        const #typescript_const: &str = #typescript;

        #to_js
        #from_js
    })
}

#[cfg(test)]
mod tests;
