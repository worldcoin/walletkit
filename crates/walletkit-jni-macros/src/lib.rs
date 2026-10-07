//! Generates the typed JNI entry points of the `walletkit` crate.
//!
//! `#[jni_export]` keeps the annotated Rust function unchanged and adds an
//! `extern "system"` function named after the Kotlin `external fun`. The generated
//! function converts each JNI argument with `FromJni`, calls the Rust function, converts
//! the result with `IntoJni`, and turns errors and panics into pending Java exceptions.
//! The conversions live in `crate::native::jni`; this macro only writes glue.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use std::fmt::Write as _;
use syn::{
    parse_macro_input, FnArg, GenericArgument, ItemFn, LitStr, Pat, PathArguments,
    ReturnType, Type,
};

const DEFAULT_CLASS: &str = "org/world/walletkit/NativeBridge";

/// Exports a Rust function as a static JNI method.
///
/// The JNI method name is the function name in lower camel case. The optional
/// `class = "org/world/walletkit/NativeBridge"` argument selects the declaring class.
/// Functions return either `T` or `Result<T>` where the error converts into the
/// runtime's failure type.
#[proc_macro_attribute]
pub fn jni_export(attribute: TokenStream, item: TokenStream) -> TokenStream {
    let mut class = DEFAULT_CLASS.to_owned();
    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("class") {
            class = meta.value()?.parse::<LitStr>()?.value();
            Ok(())
        } else {
            Err(meta.error("expected `class = \"...\"`"))
        }
    });
    parse_macro_input!(attribute with parser);
    let function = parse_macro_input!(item as ItemFn);
    expand(&class, &function)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand(class: &str, function: &ItemFn) -> syn::Result<TokenStream2> {
    let runtime = quote!(crate::native::jni);
    let name = &function.sig.ident;
    let method = lower_camel_case(&name.to_string());
    let symbol = format_ident!("Java_{}_{}", mangle(class), mangle(&method));

    let mut parameters = Vec::new();
    let mut conversions = Vec::new();
    let mut arguments = Vec::new();
    for input in &function.sig.inputs {
        let FnArg::Typed(argument) = input else {
            return Err(syn::Error::new_spanned(input, "methods cannot be exported"));
        };
        let Pat::Ident(pattern) = argument.pat.as_ref() else {
            return Err(syn::Error::new_spanned(
                &argument.pat,
                "expected an identifier",
            ));
        };
        let ident = &pattern.ident;
        let ty = &argument.ty;
        parameters.push(quote!(#ident: <#ty as #runtime::FromJni<'local>>::Raw));
        conversions.push(
            quote!(let #ident = <#ty as #runtime::FromJni<'local>>::from_jni(env, #ident)?;),
        );
        arguments.push(ident);
    }

    let call = quote!(#name(#(#arguments),*));
    let (output, result) = match &function.sig.output {
        ReturnType::Default => (quote!(()), quote!(#call)),
        ReturnType::Type(_, ty) => match result_ok_type(ty) {
            Some(ok) => (quote!(#ok), quote!(#call?)),
            None => (quote!(#ty), call),
        },
    };

    Ok(quote! {
        #[allow(clippy::needless_pass_by_value)]
        #function

        #[no_mangle]
        pub extern "system" fn #symbol<'local>(
            mut env: ::jni::JNIEnv<'local>,
            _class: ::jni::objects::JClass<'local>,
            #(#parameters),*
        ) -> <#output as #runtime::IntoJni<'local>>::Raw {
            #runtime::boundary(&mut env, |env| {
                #(#conversions)*
                let result: #output = #result;
                #runtime::IntoJni::into_jni(result, env)
            })
        }
    })
}

/// Returns `T` for `Result<T>` or `Result<T, E>`.
fn result_ok_type(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else { return None };
    let segment = path.path.segments.last()?;
    if segment.ident != "Result" {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    match arguments.args.first()? {
        GenericArgument::Type(ok) => Some(ok),
        _ => None,
    }
}

fn lower_camel_case(name: &str) -> String {
    let mut output = String::with_capacity(name.len());
    let mut upper = false;
    for character in name.chars() {
        if character == '_' {
            upper = true;
        } else if upper {
            output.extend(character.to_uppercase());
            upper = false;
        } else {
            output.push(character);
        }
    }
    output
}

/// JNI short-name mangling for ASCII identifiers and `/`-separated class names.
fn mangle(name: &str) -> String {
    let mut output = String::with_capacity(name.len());
    for character in name.chars() {
        match character {
            '/' | '.' => output.push('_'),
            '_' => output.push_str("_1"),
            ';' => output.push_str("_2"),
            '[' => output.push_str("_3"),
            character if character.is_ascii_alphanumeric() => output.push(character),
            character => {
                let mut units = [0; 2];
                for unit in character.encode_utf16(&mut units) {
                    write!(output, "_0{unit:04x}")
                        .expect("writing to a String cannot fail");
                }
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_jni_specification() {
        assert_eq!(
            lower_camel_case("credential_store_list_activities"),
            "credentialStoreListActivities"
        );
        assert_eq!(
            lower_camel_case("field_element_from_u64"),
            "fieldElementFromU64"
        );
        assert_eq!(
            mangle("org/world/walletkit/NativeBridge"),
            "org_world_walletkit_NativeBridge"
        );
        assert_eq!(mangle("a_b;[é"), "a_1b_2_3_000e9");
    }
}
