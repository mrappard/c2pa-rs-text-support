// Generates C2PA 2.4 text conformance test vectors: signed HTML, unstructured text and
// structured text assets, broken variants of them, and the crJSON a validator produces
// for each (or the error when the asset is rejected before a manifest can be read).
//
// Usage: cargo run --example text_conformance_vectors --features "file_io spec_2_4_text" -- <output dir>

use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use c2pa::{create_signer, Builder, Context, Reader, SigningAlg};
use serde_json::{json, Value};

const SIGNCERT: &[u8] = include_bytes!("../tests/fixtures/certs/es256.pub");
const PKEY: &[u8] = include_bytes!("../tests/fixtures/certs/es256.pem");

const HUMAN_WRITTEN: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation";

const HTML_DOC: &str = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Example</title>\n</head>\n<body>\n<p>Content here.</p>\n</body>\n</html>\n";
const TXT_DOC: &str = "The quick brown fox jumps over the lazy dog.\nSecond line.\n";
const CSV_DOC: &str = "name,city\nAda,London\nGrace,New York\n";
const MD_DOC: &str = "# Title\n\nSome markdown text.\n";

struct Case {
    name: &'static str,
    /// file extension, which is also the format passed to the SDK
    ext: &'static str,
    media_type: &'static str,
    description: &'static str,
    asset: Vec<u8>,
    /// a sidecar manifest store written next to the asset as <name>.c2pa
    sidecar: Option<Vec<u8>>,
}

fn definition(actions: Value) -> Value {
    json!({
        "claim_generator_info": [{ "name": "text-conformance-vectors", "version": "1.0", "specVersion": "2.4" }],
        "title": "text conformance vector",
        "assertions": [{
            "label": "c2pa.actions",
            "created": true,
            "data": { "allActionsIncluded": true, "actions": actions }
        }]
    })
}

fn created() -> Value {
    json!([{ "action": "c2pa.created", "digitalSourceType": HUMAN_WRITTEN }])
}

fn sign_with(builder: &mut Builder, format: &str, content: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let signer = create_signer::from_keys(SIGNCERT, PKEY, SigningAlg::Es256, None)?;
    let mut dest = Cursor::new(Vec::new());
    let manifest = builder
        .sign(signer.as_ref(), format, &mut Cursor::new(content.to_vec()), &mut dest)
        .with_context(|| format!("signing {format}"))?;
    Ok((dest.into_inner(), manifest))
}

fn sign(format: &str, content: &[u8]) -> Result<Vec<u8>> {
    let mut builder = Builder::from_context(Context::new()).with_definition(definition(created()))?;
    Ok(sign_with(&mut builder, format, content)?.0)
}

/// Signs an edit of an already signed asset: the original becomes the parentOf
/// ingredient and the first action is c2pa.opened.
fn sign_edit(format: &str, original: &[u8], edited_text: &[u8]) -> Result<Vec<u8>> {
    let mut builder = Builder::from_context(Context::new())
        .with_definition(definition(json!([
            { "action": "c2pa.opened", "parameters": { "ingredientIds": ["original"] } },
            { "action": "c2pa.edited", "digitalSourceType": HUMAN_WRITTEN }
        ])))?;
    builder.add_ingredient_from_stream(
        json!({ "title": "original", "relationship": "parentOf", "label": "original" }).to_string(),
        format,
        &mut Cursor::new(original.to_vec()),
    )?;
    Ok(sign_with(&mut builder, format, edited_text)?.0)
}

fn replace_once(asset: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let pos = asset
        .windows(from.len())
        .position(|w| w == from)
        .expect("text to replace");
    [&asset[..pos], to, &asset[pos + from.len()..]].concat()
}

/// Byte offset of the U+FEFF that starts the unstructured text wrapper.
fn wrapper_start(asset: &[u8]) -> usize {
    asset
        .windows(3)
        .rposition(|w| w == [0xEF, 0xBB, 0xBF])
        .expect("wrapper")
}

fn cases() -> Result<Vec<Case>> {
    let mut cases = Vec::new();
    let mut add = |name, ext, media_type, description, asset: Vec<u8>, sidecar| {
        cases.push(Case { name, ext, media_type, description, asset, sidecar })
    };

    // Unstructured text (Spec 2.4 §A.8)
    let txt = sign("txt", TXT_DOC.as_bytes())?;
    add("txt-valid", "txt", "text/plain", "Signed plain text; wrapper at the end of the text.", txt.clone(), None);
    add("txt-tampered", "txt", "text/plain", "One word changed after signing; the wrapper still matches the exclusion.", replace_once(&txt, b"quick", b"quack"), None);
    add(
        "txt-inserted-text",
        "txt",
        "text/plain",
        "Text inserted after signing moves the wrapper, so the exclusion no longer matches it (assertion.dataHash.malformed).",
        replace_once(&txt, b"Second line.", b"Second line, edited."),
        None,
    );
    let nfc = sign("txt", "Caf\u{00E9} au lait.\n".as_bytes())?;
    let nfd = replace_once(&nfc, "Caf\u{00E9}".as_bytes(), "Cafe\u{0301}".as_bytes());
    add("txt-nfd-after-signing", "txt", "text/plain", "Signed as NFC, then stored as NFD (same text, different bytes, exclusion moved). NFD is not tampering, but the exclusion no longer matches the wrapper.", nfd, None);
    let mut two = txt.clone();
    two.extend_from_slice(&txt[wrapper_start(&txt)..]);
    add("txt-two-wrappers", "txt", "text/plain", "The wrapper is duplicated (manifest.text.multipleWrappers).", two, None);
    let start = wrapper_start(&txt);
    add("txt-truncated-wrapper", "txt", "text/plain", "Partial copy: the wrapper is cut off after its header (manifest.text.corruptedWrapper).", txt[..start + 3 + 40 * 4].to_vec(), None);
    add("txt-edited", "txt", "text/plain", "An edit of txt-valid: first action c2pa.opened with txt-valid as the parentOf ingredient.", sign_edit("txt", &txt, b"The quick brown fox jumps over the lazy cat.\n")?, None);
    let csv = sign("csv", CSV_DOC.as_bytes())?;
    add("csv-valid", "csv", "text/csv", "Signed CSV using the unstructured text wrapper.", csv, None);

    // HTML (Spec 2.4 §A.7)
    let html = sign("html", HTML_DOC.as_bytes())?;
    add("html-valid", "html", "text/html", "Manifest embedded as <script type=\"application/c2pa\"> in the head; one exclusion.", html.clone(), None);
    add("html-tampered", "html", "text/html", "Body text changed after signing.", replace_once(&html, b"Content here.", b"Content HERE."), None);
    let html_str = String::from_utf8(html.clone())?;
    add(
        "html-two-manifests",
        "html",
        "text/html",
        "A <link rel=\"c2pa-manifest\"> added next to the embedded script (manifest.html.multipleManifests).",
        html_str.replace("</head>", "<link rel=\"c2pa-manifest\" href=\"https://example.com/manifest.c2pa\"></head>").into_bytes(),
        None,
    );
    let mut linked = Builder::from_context(Context::new()).with_definition(definition(created()))?;
    linked.set_no_embed(true);
    linked.set_remote_url("https://example.com/html-linked.c2pa");
    let (linked_html, linked_manifest) = sign_with(&mut linked, "html", HTML_DOC.as_bytes())?;
    add("html-linked", "html", "text/html", "External manifest referenced with <link rel=\"c2pa-manifest\">; the data hash has no exclusions. Validated from the html-linked.c2pa sidecar.", linked_html, Some(linked_manifest));

    // Structured text (Spec 2.4 §A.9)
    let md = sign("md", MD_DOC.as_bytes())?;
    add("md-valid", "md", "text/markdown", "Manifest block in an HTML comment on the first line.", md.clone(), None);
    add("md-tampered", "md", "text/markdown", "Body text changed after signing.", replace_once(&md, b"Some markdown", b"Some MARKDOWN"), None);
    let block_end = md.iter().position(|b| *b == b'\n').expect("block line") + 1;
    add("md-two-blocks", "md", "text/markdown", "The manifest block line is duplicated (manifest.structuredText.multipleReferences).", [&md[..block_end], &md[..]].concat(), None);
    add("md-empty-reference", "md", "text/markdown", "Manifest block with nothing between the delimiters (manifest.structuredText.emptyReference).", b"<!-- -----BEGIN C2PA MANIFEST-----   -----END C2PA MANIFEST----- -->\n# Title\n".to_vec(), None);
    add("md-malformed-reference", "md", "text/markdown", "Manifest reference that is not a URL or data: URI (manifest.structuredText.malformedReference).", b"<!-- -----BEGIN C2PA MANIFEST----- not a url -----END C2PA MANIFEST----- -->\n# Title\n".to_vec(), None);
    add("md-no-resolution-path", "md", "text/markdown", "Manifest reference with a scheme that cannot be resolved (manifest.structuredText.noResolutionPath).", b"<!-- -----BEGIN C2PA MANIFEST----- ftp://example.com/manifest.c2pa -----END C2PA MANIFEST----- -->\n# Title\n".to_vec(), None);
    add("md-missing-end-delimiter", "md", "text/markdown", "Manifest block without its end delimiter (manifest.structuredText.noManifest).", b"<!-- -----BEGIN C2PA MANIFEST----- data:application/c2pa;base64,AAAA\n# Title\n".to_vec(), None);

    Ok(cases)
}

fn write_case(dir: &Path, case: &Case) -> Result<Value> {
    let asset_path = dir.join(format!("{}.{}", case.name, case.ext));
    fs::write(&asset_path, &case.asset)?;
    if let Some(sidecar) = &case.sidecar {
        fs::write(dir.join(format!("{}.c2pa", case.name)), sidecar)?;
    }

    let mut entry = json!({
        "name": case.name,
        "asset": asset_path.file_name().unwrap().to_string_lossy(),
        "mediaType": case.media_type,
        "description": case.description,
    });

    // a case with a sidecar is validated against it directly: its asset also references a
    // remote URL, which this generator does not fetch
    let read = match &case.sidecar {
        Some(sidecar) => Reader::from_context(Context::new()).with_manifest_data_and_stream(
            sidecar,
            case.media_type,
            Cursor::new(case.asset.clone()),
        ),
        None => Reader::from_context(Context::new()).with_file(&asset_path),
    };
    match read {
        Ok(reader) => {
            let crjson_name = format!("{}.crjson.json", case.name);
            let crjson: Value = serde_json::from_str(&reader.crjson())?;
            fs::write(dir.join(&crjson_name), serde_json::to_string_pretty(&crjson)? + "\n")?;
            entry["crjson"] = json!(crjson_name);
        }
        Err(e) => {
            // the manifest store could not be located; crJSON reports the failure code
            entry["readError"] = json!(format!("{e}"));
            if let Some(crjson) = Reader::crjson_for_load_error(&e) {
                let crjson_name = format!("{}.crjson.json", case.name);
                fs::write(dir.join(&crjson_name), crjson + "\n")?;
                entry["crjson"] = json!(crjson_name);
            }
        }
    }
    Ok(entry)
}

fn main() -> Result<()> {
    let dir = PathBuf::from(std::env::args().nth(1).context("usage: text_conformance_vectors <output dir>")?);
    fs::create_dir_all(&dir)?;

    let entries = cases()?
        .iter()
        .map(|case| write_case(&dir, case))
        .collect::<Result<Vec<_>>>()?;

    let index = json!({
        "generator": "c2pa-rs-text-support sdk/examples/text_conformance_vectors.rs",
        "spec": "C2PA 2.4 (HTML §A.7, unstructured text §A.8, structured text §A.9)",
        "signer": "sdk/tests/fixtures/certs/es256.pub (test certificate, not on a trust list)",
        "cases": entries,
    });
    fs::write(dir.join("cases.json"), serde_json::to_string_pretty(&index)? + "\n")?;
    println!("wrote {} cases to {}", index["cases"].as_array().map_or(0, Vec::len), dir.display());
    Ok(())
}
