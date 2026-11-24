//! The parsed `#[js_type]` declaration.

use heck::{ToLowerCamelCase, ToSnakeCase};
use proc_macro2::{Span, TokenStream};
use quote::ToTokens;
use syn::{
    parse::Parser, spanned::Spanned, Attribute, Data, DataEnum, DeriveInput, Error,
    Fields, Ident, LitStr, Path, Type,
};

pub struct JsType {
    pub ident: Ident,
    pub remote: Option<Path>,
    pub input: bool,
    pub output: bool,
    pub readonly: bool,
    /// Converts the whole value from JavaScript, instead of field by field.
    pub from_js: Option<Path>,
    pub docs: Vec<String>,
    pub shape: Shape,
}

pub enum Shape {
    Struct(Vec<Field>),
    /// A union of the variant names as strings.
    Strings(Vec<Variant>),
    /// A union of objects whose `tag` property names the variant.
    Tagged {
        tag: String,
        variants: Vec<Variant>,
    },
}

pub struct Variant {
    pub ident: Ident,
    pub js_name: String,
    pub fields: Vec<Field>,
}

pub struct Field {
    pub ident: Ident,
    pub js_name: String,
    pub ty: Type,
    pub docs: Vec<String>,
    pub ts: Option<String>,
    pub to_js: Option<Path>,
    pub from_js: Option<Path>,
    pub flatten: bool,
}

#[derive(Clone, Copy)]
enum Case {
    Snake,
    Lower,
}

impl JsType {
    pub fn parse(attr: TokenStream, item: &DeriveInput) -> syn::Result<Self> {
        let mut remote = None;
        let mut input = false;
        let mut output = false;
        let mut readonly = false;
        let mut from_js = None;
        let mut tag = None;
        let mut case = Case::Snake;
        let parser = syn::meta::parser(|meta| {
            if meta.path.is_ident("remote") {
                remote = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("input") {
                input = true;
            } else if meta.path.is_ident("output") {
                output = true;
            } else if meta.path.is_ident("readonly") {
                readonly = true;
            } else if meta.path.is_ident("from_js") {
                from_js = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("tag") {
                tag = Some(meta.value()?.parse::<LitStr>()?.value());
            } else if meta.path.is_ident("rename_all") {
                let rule: LitStr = meta.value()?.parse()?;
                case = match rule.value().as_str() {
                    "snake_case" => Case::Snake,
                    "lowercase" => Case::Lower,
                    _ => {
                        return Err(Error::new(
                            rule.span(),
                            "expected \"snake_case\" or \"lowercase\"",
                        ))
                    }
                };
            } else {
                return Err(meta.error("unknown `js_type` option"));
            }
            Ok(())
        });
        parser.parse2(attr)?;

        if !input && !output {
            return Err(Error::new(
                Span::call_site(),
                "`js_type` needs `input`, `output` or both",
            ));
        }
        if !item.generics.params.is_empty() {
            return Err(Error::new(
                item.generics.span(),
                "`js_type` does not support generics",
            ));
        }

        let shape = match &item.data {
            Data::Struct(data) => {
                if tag.is_some() {
                    return Err(Error::new(item.ident.span(), "`tag` is for enums"));
                }
                Shape::Struct(parse_fields(&data.fields)?)
            }
            Data::Enum(data) => {
                let variants = parse_variants(data, case)?;
                if let Some(tag) = tag {
                    Shape::Tagged { tag, variants }
                } else {
                    if let Some(variant) =
                        variants.iter().find(|variant| !variant.fields.is_empty())
                    {
                        return Err(Error::new(
                            variant.ident.span(),
                            "an enum with fields needs a `tag`",
                        ));
                    }
                    Shape::Strings(variants)
                }
            }
            Data::Union(_) => {
                return Err(Error::new(item.ident.span(), "unions are not supported"))
            }
        };

        let model = Self {
            ident: item.ident.clone(),
            remote,
            input,
            output,
            readonly,
            from_js,
            docs: docs(&item.attrs),
            shape,
        };
        model.validate()?;
        Ok(model)
    }

    /// The type that receives the conversions: the remote type, or the declared one.
    pub fn target(&self) -> TokenStream {
        self.remote
            .as_ref()
            .map_or_else(|| self.ident.to_token_stream(), ToTokens::to_token_stream)
    }

    fn validate(&self) -> syn::Result<()> {
        if self.from_js.is_some() && !self.input {
            return Err(Error::new(self.ident.span(), "`from_js` needs `input`"));
        }
        if self.input && matches!(self.shape, Shape::Tagged { .. }) {
            return Err(Error::new(
                self.ident.span(),
                "tagged enums support only `output`",
            ));
        }
        let field_groups: Vec<&[Field]> = match &self.shape {
            Shape::Struct(fields) => vec![fields],
            Shape::Strings(_) => vec![],
            Shape::Tagged { variants, .. } => {
                variants.iter().map(|variant| &variant.fields[..]).collect()
            }
        };
        for fields in field_groups {
            if self.from_js.is_some() {
                if let Some(field) = fields.iter().find(|field| field.from_js.is_some())
                {
                    return Err(Error::new(
                        field.ident.span(),
                        "a field `from_js` has no effect with a container `from_js`",
                    ));
                }
            }
            let mut flattened = fields.iter().filter(|field| field.flatten);
            if let Some(field) = flattened.next() {
                if self.input {
                    return Err(Error::new(
                        field.ident.span(),
                        "`flatten` supports only `output`",
                    ));
                }
                if field.to_js.is_some() {
                    return Err(Error::new(
                        field.ident.span(),
                        "`flatten` cannot be combined with `to_js`",
                    ));
                }
            }
            if let Some(field) = flattened.next() {
                return Err(Error::new(
                    field.ident.span(),
                    "only one field can be flattened",
                ));
            }
        }
        Ok(())
    }
}

impl Case {
    fn apply(self, ident: &str) -> String {
        match self {
            Self::Snake => ident.to_snake_case(),
            Self::Lower => ident.to_lowercase(),
        }
    }
}

fn parse_variants(data: &DataEnum, case: Case) -> syn::Result<Vec<Variant>> {
    data.variants
        .iter()
        .map(|variant| {
            Ok(Variant {
                ident: variant.ident.clone(),
                js_name: rename(&variant.attrs)?
                    .unwrap_or_else(|| case.apply(&variant.ident.to_string())),
                fields: parse_fields(&variant.fields)?,
            })
        })
        .collect()
}

fn parse_fields(fields: &Fields) -> syn::Result<Vec<Field>> {
    match fields {
        Fields::Unit => Ok(Vec::new()),
        Fields::Unnamed(fields) => Err(Error::new(
            fields.span(),
            "tuple fields are not supported; name them",
        )),
        Fields::Named(fields) => fields
            .named
            .iter()
            .map(|field| {
                let ident = field.ident.clone().expect("named field");
                let mut parsed = Field {
                    js_name: ident.to_string().to_lower_camel_case(),
                    ident,
                    ty: field.ty.clone(),
                    docs: docs(&field.attrs),
                    ts: None,
                    to_js: None,
                    from_js: None,
                    flatten: false,
                };
                for attr in js_attributes(&field.attrs) {
                    attr.parse_nested_meta(|meta| {
                        if meta.path.is_ident("rename") {
                            parsed.js_name = meta.value()?.parse::<LitStr>()?.value();
                        } else if meta.path.is_ident("ts") {
                            parsed.ts = Some(meta.value()?.parse::<LitStr>()?.value());
                        } else if meta.path.is_ident("to_js") {
                            parsed.to_js = Some(meta.value()?.parse()?);
                        } else if meta.path.is_ident("from_js") {
                            parsed.from_js = Some(meta.value()?.parse()?);
                        } else if meta.path.is_ident("flatten") {
                            parsed.flatten = true;
                        } else {
                            return Err(meta.error("unknown `js` field option"));
                        }
                        Ok(())
                    })?;
                }
                Ok(parsed)
            })
            .collect(),
    }
}

fn rename(attrs: &[Attribute]) -> syn::Result<Option<String>> {
    let mut name = None;
    for attr in js_attributes(attrs) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                name = Some(meta.value()?.parse::<LitStr>()?.value());
                Ok(())
            } else {
                Err(meta.error("variants support only `rename`"))
            }
        })?;
    }
    Ok(name)
}

fn js_attributes(attrs: &[Attribute]) -> impl Iterator<Item = &Attribute> {
    attrs.iter().filter(|attr| attr.path().is_ident("js"))
}

fn docs(attrs: &[Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter_map(|attr| match &attr.meta {
            syn::Meta::NameValue(meta) if meta.path.is_ident("doc") => {
                match &meta.value {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(doc),
                        ..
                    }) => {
                        let doc = doc.value();
                        Some(doc.strip_prefix(' ').unwrap_or(&doc).to_owned())
                    }
                    _ => None,
                }
            }
            _ => None,
        })
        .collect()
}

/// Removes the `#[js(...)]` helper attributes, which the compiler would reject.
pub fn strip_js_attributes(item: &mut DeriveInput) {
    let strip_fields = |fields: &mut Fields| {
        for field in fields.iter_mut() {
            field.attrs.retain(|attr| !attr.path().is_ident("js"));
        }
    };
    match &mut item.data {
        Data::Struct(data) => strip_fields(&mut data.fields),
        Data::Enum(data) => {
            for variant in &mut data.variants {
                variant.attrs.retain(|attr| !attr.path().is_ident("js"));
                strip_fields(&mut variant.fields);
            }
        }
        Data::Union(_) => {}
    }
}
