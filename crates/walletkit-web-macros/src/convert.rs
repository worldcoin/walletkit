//! Generates the `ToJs` and `FromJs` implementations of a [`JsType`].

use proc_macro2::TokenStream;
use quote::quote;

use crate::model::{Field, JsType, Shape};

pub fn to_js(model: &JsType) -> TokenStream {
    let target = model.target();
    let checked = model.remote.is_some();
    let body = match &model.shape {
        Shape::Struct(fields) => {
            let bindings = fields.iter().map(|field| &field.ident);
            let object = object_to_js(fields, None, checked);
            quote! {
                let Self { #(#bindings),* } = self;
                #object
            }
        }
        Shape::Strings(variants) => {
            let arms = variants.iter().map(|variant| {
                let (ident, js_name) = (&variant.ident, &variant.js_name);
                quote!(Self::#ident => #js_name)
            });
            quote! {
                Ok(::wasm_bindgen::JsValue::from_str(match self { #(#arms),* }))
            }
        }
        Shape::Tagged { tag, variants } => {
            let arms = variants.iter().map(|variant| {
                let ident = &variant.ident;
                let bindings = variant.fields.iter().map(|field| &field.ident);
                let object = object_to_js(
                    &variant.fields,
                    Some((tag, &variant.js_name)),
                    checked,
                );
                quote!(Self::#ident { #(#bindings),* } => { #object })
            });
            quote!(match self { #(#arms)* })
        }
    };
    quote! {
        impl crate::js::ToJs for #target {
            fn to_js(
                &self,
            ) -> ::core::result::Result<::wasm_bindgen::JsValue, ::wasm_bindgen::JsValue> {
                #body
            }
        }
    }
}

/// Builds the object for `fields`, which are bound by reference.
fn object_to_js(
    fields: &[Field],
    tag: Option<(&String, &String)>,
    checked: bool,
) -> TokenStream {
    let checks = fields
        .iter()
        .filter(|field| checked && field.to_js.is_none())
        .map(schema_check);
    let object = fields.iter().find(|field| field.flatten).map_or_else(
        || quote!(::js_sys::Object::new()),
        |field| {
            let ident = &field.ident;
            quote!(crate::js::into_object(crate::js::ToJs::to_js(#ident)?)?)
        },
    );
    let tag = tag.map(|(tag, name)| {
        quote!(crate::js::set(&__object, #tag, &::wasm_bindgen::JsValue::from_str(#name))?;)
    });
    let properties = fields.iter().filter(|field| !field.flatten).map(|field| {
        let (ident, js_name) = (&field.ident, &field.js_name);
        let value = field.to_js.as_ref().map_or_else(
            || quote!(crate::js::ToJs::to_js(#ident)?),
            |convert| quote!(#convert(#ident)?),
        );
        quote!(crate::js::set(&__object, #js_name, &#value)?;)
    });
    quote! {
        #(#checks)*
        let __object = #object;
        #tag
        #(#properties)*
        Ok(__object.into())
    }
}

pub fn from_js(model: &JsType) -> TokenStream {
    let target = model.target();
    let body = match (&model.from_js, &model.shape) {
        (Some(convert), Shape::Struct(fields)) if model.remote.is_some() => {
            // The conversion builds the value itself, so check the whole schema here.
            let bindings = fields.iter().map(|field| &field.ident);
            let checks = fields.iter().map(schema_check);
            quote! {
                let __result = #convert(&__value, __name)?;
                let Self { #(#bindings),* } = &__result;
                #(#checks)*
                Ok(__result)
            }
        }
        (Some(convert), _) => quote!(#convert(&__value, __name)),
        (None, Shape::Struct(fields)) => {
            let values = fields.iter().map(|field| {
                let (ident, js_name) = (&field.ident, &field.js_name);
                let value = quote!(crate::js::get(&__object, #js_name)?);
                let value = field.from_js.as_ref().map_or_else(
                    || quote!(crate::js::FromJs::from_js(#value, #js_name)?),
                    |convert| quote!(#convert(&#value, #js_name)?),
                );
                quote!(#ident: #value)
            });
            let checked: Vec<&Field> = fields
                .iter()
                .filter(|field| model.remote.is_some() && field.from_js.is_none())
                .collect();
            let bindings = checked.iter().map(|field| &field.ident);
            let checks = checked.iter().copied().map(schema_check);
            quote! {
                let __object = crate::js::expect_object(__value, __name)?;
                let __result = Self { #(#values),* };
                let Self { #(#bindings,)* .. } = &__result;
                #(#checks)*
                Ok(__result)
            }
        }
        (None, Shape::Strings(variants)) => {
            let arms = variants.iter().map(|variant| {
                let (ident, js_name) = (&variant.ident, &variant.js_name);
                quote!(#js_name => Ok(Self::#ident))
            });
            let idents = variants.iter().map(|variant| &variant.ident);
            quote! {
                // Fails to compile when the enum gains a variant the declaration lacks.
                let _ = |__variant: &Self| match __variant { #(Self::#idents)|* => () };
                let ::core::option::Option::Some(__text) = __value.as_string() else {
                    return Err(crate::js::expected(__name, "a string"));
                };
                match __text.as_str() {
                    #(#arms,)*
                    _ => Err(crate::js::unknown_value(__name, &__text)),
                }
            }
        }
        (None, Shape::Tagged { .. }) => unreachable!("rejected during parsing"),
    };
    quote! {
        impl crate::js::FromJs for #target {
            fn from_js(
                __value: ::wasm_bindgen::JsValue,
                __name: &str,
            ) -> ::core::result::Result<Self, ::wasm_bindgen::JsValue> {
                #body
            }
        }
    }
}

/// Checks that the remote field bound to `field.ident` matches the declared type.
fn schema_check(field: &Field) -> TokenStream {
    let (ident, ty) = (&field.ident, &field.ty);
    quote!(crate::js::assert_schema::<_, #ty>(#ident);)
}
