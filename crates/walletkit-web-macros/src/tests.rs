use indoc::indoc;
use quote::quote;
use test_case::test_case;

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
                r#type: String,
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
              type: string;
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

#[test_case("", "struct A { a: u8 }", "`input`, `output`"; "no direction")]
#[test_case("output", "enum A { B { c: u8 } }", "needs a `tag`"; "enum fields without a tag")]
#[test_case(r#"input, tag = "t""#, "enum A { B }", "only `output`"; "tagged input")]
#[test_case("input", "struct A { #[js(flatten)] b: B }", "only `output`"; "flattened input")]
#[test_case("output", "struct A(u8);", "tuple fields"; "tuple struct")]
#[test_case("output", "struct A { b: HashMap<u8, u8> }", "no TypeScript mapping"; "unmapped type")]
#[test_case("output", "struct A { b: [u8; N] }", "no TypeScript mapping"; "array of unknown length")]
#[test_case("output, from_js = parse", "struct A { b: u8 }", "`from_js` needs `input`"; "container from_js without input")]
#[test_case(r#"output, tag = "reason""#, "enum A { B { reason: String } }", "`reason` is already used"; "field named like the tag")]
#[test_case("output", r#"struct A { a_b: u8, #[js(rename = "aB")] c: u8 }"#, "`aB` is already used"; "duplicate field name")]
#[test_case(r#"output, rename_all = "lowercase""#, "struct A { b: u8 }", "are for enums"; "rename_all on a struct")]
#[test_case("output, readonly", "enum A { B }", "no effect on a string union"; "readonly string union")]
#[test_case("output, bogus", "struct A { b: u8 }", "unknown `js_type` option"; "unknown option")]
fn invalid_declaration_is_rejected(attr: &str, item: &str, message: &str) {
    let error = error(attr.parse().unwrap(), item.parse().unwrap());
    assert!(error.contains(message), "{error}");
}
