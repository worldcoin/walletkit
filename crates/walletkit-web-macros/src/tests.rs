use indoc::indoc;
use quote::quote;

use crate::{model::JsType, ts};

fn typescript(
    attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream,
) -> String {
    let item = syn::parse2(item).unwrap();
    let ts = ts::render(&JsType::parse(attr, &item).unwrap()).unwrap();
    // Each declaration starts on a new line of the generated `.d.ts`.
    ts.strip_prefix('\n').unwrap().to_owned()
}

fn error(attr: proc_macro2::TokenStream, item: proc_macro2::TokenStream) -> String {
    let item = syn::parse2(item).unwrap();
    match JsType::parse(attr, &item).and_then(|model| ts::render(&model)) {
        Ok(_) => panic!("expected an error"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn record_becomes_an_interface_with_camel_case_properties() {
    let ts = typescript(
        quote!(remote = core::Entry, input, output),
        quote! {
            /// A stored entry.
            struct Entry {
                id: Option<u64>,
                /// Local only.
                ///
                /// Keep out of logs.
                client_id: String,
                count: u32,
                done: bool,
                payload: Vec<u8>,
                issuer_schema_ids: Vec<u64>,
                tags: Vec<Option<String>>,
                #[js(rename = "kind", ts = "3 | 4")]
                protocol: ProtocolVersion,
                nested: Other,
            }
        },
    );
    assert_eq!(
        ts,
        indoc! {"
            /** A stored entry. */
            export interface Entry {
              id?: bigint;
              /**
               * Local only.
               *
               * Keep out of logs.
               */
              clientId: string;
              count: number;
              done: boolean;
              payload: Uint8Array;
              issuerSchemaIds: bigint[];
              tags: (string | undefined)[];
              kind: 3 | 4;
              nested: Other;
            }
        "}
    );
}

#[test]
fn readonly_marks_properties_and_arrays() {
    let ts = typescript(
        quote!(output, readonly),
        quote! {
            struct Prompt {
                targets: [Target; 3],
                ids: Vec<u64>,
            }
        },
    );
    assert_eq!(
        ts,
        indoc! {"
            export interface Prompt {
              readonly targets: readonly [Target, Target, Target];
              readonly ids: readonly bigint[];
            }
        "}
    );
}

#[test]
fn unit_enum_becomes_a_string_union() {
    let ts = typescript(
        quote!(remote = core::Reason, input, rename_all = "lowercase"),
        quote! {
            enum Reason { NetworkError, Timeout }
        },
    );
    assert_eq!(
        ts,
        indoc! {r#"
            export type Reason =
              | "networkerror"
              | "timeout";
        "#}
    );

    let ts = typescript(
        quote!(output),
        quote! {
            enum Failure { InvalidImage, #[js(rename = "other")] PoseMismatch }
        },
    );
    assert_eq!(
        ts,
        indoc! {r#"
            export type Failure =
              | "invalid_image"
              | "other";
        "#}
    );
}

#[test]
fn tagged_enum_becomes_a_discriminated_union() {
    let ts = typescript(
        quote!(remote = core::Status, output, tag = "state"),
        quote! {
            enum Status {
                Queued,
                Failed { error: String, error_code: Option<String> },
                Rejected { #[js(flatten)] reason: Failure },
            }
        },
    );
    assert_eq!(
        ts,
        indoc! {r#"
            export type Status =
              | { state: "queued" }
              | { state: "failed"; error: string; errorCode?: string }
              | ({ state: "rejected" } & Failure);
        "#}
    );
}

#[test]
fn record_with_a_flattened_field_becomes_an_intersection() {
    let ts = typescript(
        quote!(output),
        quote! {
            struct Outcome { attempt: u32, #[js(flatten)] result: Result }
        },
    );
    assert_eq!(
        ts,
        indoc! {"
            export type Outcome = {
              attempt: number;
            } & Result;
        "}
    );
}

#[test]
fn invalid_declarations_are_rejected() {
    assert!(error(
        quote!(),
        quote!(
            struct A {
                a: u8,
            }
        )
    )
    .contains("`input`, `output`"));
    assert!(error(
        quote!(output),
        quote!(
            enum A {
                B { c: u8 },
            }
        )
    )
    .contains("needs a `tag`"));
    assert!(error(
        quote!(input, tag = "t"),
        quote!(
            enum A {
                B,
            }
        )
    )
    .contains("only `output`"));
    assert!(error(
        quote!(input),
        quote!(
            struct A {
                #[js(flatten)]
                b: B,
            }
        )
    )
    .contains("only `output`"));
    assert!(error(
        quote!(output),
        quote!(
            struct A(u8);
        )
    )
    .contains("tuple fields"));
    assert!(error(
        quote!(output),
        quote!(
            struct A {
                b: HashMap<u8, u8>,
            }
        )
    )
    .contains("no TypeScript mapping"));
    assert!(error(
        quote!(output),
        quote!(
            struct A {
                b: [u8; N],
            }
        )
    )
    .contains("no TypeScript mapping"));
    assert!(error(
        quote!(output, from_js = parse),
        quote!(
            struct A {
                b: u8,
            }
        )
    )
    .contains("`from_js` needs `input`"));
    assert!(error(
        quote!(output, bogus),
        quote!(
            struct A {
                b: u8,
            }
        )
    )
    .contains("unknown `js_type` option"));
}
