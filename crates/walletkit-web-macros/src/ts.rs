//! Renders the TypeScript declaration of a [`JsType`].

use std::fmt::Write as _;

use syn::{spanned::Spanned, Error, Expr, GenericArgument, PathArguments, Type};

use crate::model::{Field, JsType, Shape};

pub fn render(model: &JsType) -> syn::Result<String> {
    let name = &model.ident;
    let declaration = match &model.shape {
        Shape::Struct(fields) => {
            let (properties, flattened) = properties(fields, model.readonly)?;
            let body: String = properties
                .iter()
                .map(|(docs, property)| {
                    format!("{}  {property};\n", doc_comment(docs, "  "))
                })
                .collect::<Vec<_>>()
                .concat();
            flattened.map_or_else(
                || format!("export interface {name} {{\n{body}}}"),
                |flattened| {
                    let flattened = group(&flattened);
                    format!("export type {name} = {{\n{body}}} & {flattened};")
                },
            )
        }
        Shape::Strings(variants) => {
            let members: Vec<String> = variants
                .iter()
                .map(|variant| format!("  | {}", string_literal(&variant.js_name)))
                .collect();
            format!("export type {name} =\n{};", members.join("\n"))
        }
        Shape::Tagged { tag, variants } => {
            // Variants with the same payload share one member, so a value's tag can
            // change between them, e.g. from "queued" to "batching".
            let mut groups: Vec<Group> = Vec::new();
            for variant in variants {
                let (properties, flattened) =
                    properties(&variant.fields, model.readonly)?;
                let properties: Vec<String> = properties
                    .into_iter()
                    .map(|(_, property)| property)
                    .collect();
                let mut key = properties.clone();
                key.sort();
                let tag_value = string_literal(&variant.js_name);
                match groups
                    .iter_mut()
                    .find(|group| group.key == key && group.flattened == flattened)
                {
                    Some(group) => group.tags.push(tag_value),
                    None => groups.push(Group {
                        key,
                        properties,
                        flattened,
                        tags: vec![tag_value],
                    }),
                }
            }
            let modifier = if model.readonly { "readonly " } else { "" };
            let tag = property_name(tag);
            let members: Vec<String> = groups
                .into_iter()
                .map(
                    |Group {
                         properties,
                         flattened,
                         tags,
                         ..
                     }| {
                        let properties: String = properties
                            .iter()
                            .map(|property| format!("; {property}"))
                            .collect::<Vec<_>>()
                            .concat();
                        let object = format!(
                            "{{ {modifier}{tag}: {}{properties} }}",
                            tags.join(" | ")
                        );
                        flattened.map_or_else(
                            || format!("  | {object}"),
                            |flattened| {
                                format!("  | ({object} & {})", group(&flattened))
                            },
                        )
                    },
                )
                .collect();
            format!("export type {name} =\n{};", members.join("\n"))
        }
    };
    Ok(format!("\n{}{declaration}\n", doc_comment(&model.docs, "")))
}

/// Tagged variants rendered as one union member.
struct Group {
    /// The sorted properties, so field order does not split a group.
    key: Vec<String>,
    /// The properties in the first variant's order.
    properties: Vec<String>,
    flattened: Option<String>,
    tags: Vec<String>,
}

/// A property declaration and the doc lines above it.
type Property<'a> = (&'a [String], String);

/// The properties of `fields`, and the type of the flattened field, if any.
fn properties(
    fields: &[Field],
    readonly: bool,
) -> syn::Result<(Vec<Property<'_>>, Option<String>)> {
    let mut properties = Vec::new();
    let mut flattened = None;
    for field in fields {
        let inner = option_inner(&field.ty);
        let ty = match &field.ts {
            Some(ts) => ts.clone(),
            None => ts_type(inner.unwrap_or(&field.ty), readonly)?,
        };
        if field.flatten {
            flattened = Some(ty);
            continue;
        }
        let modifier = if readonly { "readonly " } else { "" };
        let mark = if inner.is_some() { "?" } else { "" };
        properties.push((
            &field.docs[..],
            format!("{modifier}{}{mark}: {ty}", property_name(&field.js_name)),
        ));
    }
    Ok((properties, flattened))
}

/// Maps a Rust type to TypeScript. Other named types keep their name, which must be
/// the name of another `#[js_type]`.
fn ts_type(ty: &Type, readonly: bool) -> syn::Result<String> {
    let array_prefix = if readonly { "readonly " } else { "" };
    match ty {
        Type::Path(path) if path.qself.is_none() => {
            let segment = path.path.segments.last().expect("non-empty path");
            let name = segment.ident.to_string();
            match (name.as_str(), single_argument(&segment.arguments)) {
                ("bool", None) => Ok("boolean".into()),
                ("u8" | "u16" | "u32" | "i8" | "i16" | "i32" | "f32" | "f64", None) => {
                    Ok("number".into())
                }
                ("u64" | "i64" | "u128" | "i128", None) => Ok("bigint".into()),
                ("String", None) => Ok("string".into()),
                ("Vec", Some(item)) if is_u8(item) => Ok("Uint8Array".into()),
                ("Vec", Some(item)) => {
                    let item = ts_type(item, readonly)?;
                    if item.contains(' ') {
                        Ok(format!("{array_prefix}({item})[]"))
                    } else {
                        Ok(format!("{array_prefix}{item}[]"))
                    }
                }
                ("Option", Some(item)) => {
                    Ok(format!("{} | undefined", ts_type(item, readonly)?))
                }
                (_, None) if segment.arguments.is_none() => Ok(name),
                _ => Err(unsupported(ty)),
            }
        }
        Type::Array(array) => {
            let Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(length),
                ..
            }) = &array.len
            else {
                return Err(unsupported(ty));
            };
            let item = ts_type(&array.elem, readonly)?;
            let items = vec![item; length.base10_parse()?];
            Ok(format!("{array_prefix}[{}]", items.join(", ")))
        }
        _ => Err(unsupported(ty)),
    }
}

/// A property key: bare when it is an identifier, otherwise a string literal.
fn property_name(name: &str) -> String {
    if is_identifier(name) {
        name.to_owned()
    } else {
        string_literal(name)
    }
}

/// A flattened type as an intersection operand. `&` binds tighter than `|`, so
/// anything but a name is wrapped, e.g. `A | B`.
fn group(ty: &str) -> String {
    if is_identifier(ty) {
        ty.to_owned()
    } else {
        format!("({ty})")
    }
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || matches!(first, '_' | '$'))
        && chars.all(|char| char.is_ascii_alphanumeric() || matches!(char, '_' | '$'))
}

/// A double-quoted TypeScript string literal.
fn string_literal(value: &str) -> String {
    let mut literal = String::from('"');
    for char in value.chars() {
        match char {
            '"' | '\\' => {
                literal.push('\\');
                literal.push(char);
            }
            char if char.is_control() => {
                write!(literal, "\\u{:04x}", u32::from(char))
                    .expect("writing to a String");
            }
            char => literal.push(char),
        }
    }
    literal.push('"');
    literal
}

fn unsupported(ty: &Type) -> Error {
    Error::new(
        ty.span(),
        "no TypeScript mapping for this type; set it with `#[js(ts = \"...\")]`",
    )
}

pub fn option_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else { return None };
    let segment = path.path.segments.last()?;
    (segment.ident == "Option")
        .then(|| single_argument(&segment.arguments))
        .flatten()
}

fn single_argument(arguments: &PathArguments) -> Option<&Type> {
    let PathArguments::AngleBracketed(arguments) = arguments else {
        return None;
    };
    match arguments.args.first() {
        Some(GenericArgument::Type(ty)) if arguments.args.len() == 1 => Some(ty),
        _ => None,
    }
}

fn is_u8(ty: &Type) -> bool {
    matches!(ty, Type::Path(path) if path.path.is_ident("u8"))
}

fn doc_comment(docs: &[String], indent: &str) -> String {
    let lines: Vec<String> = docs
        .iter()
        .map(|line| line.trim_end().replace("*/", "*\\/"))
        .collect();
    match lines.as_slice() {
        [] => String::new(),
        [line] => format!("{indent}/** {line} */\n"),
        lines => {
            let body: Vec<String> = lines
                .iter()
                .map(|line| format!("{indent} * {line}").trim_end().to_owned())
                .collect();
            format!("{indent}/**\n{}\n{indent} */\n", body.join("\n"))
        }
    }
}
