// Generates C2PA 2.4 text conformance test vectors: signed HTML, unstructured text and
// structured text assets, broken variants of them, and the crJSON a validator produces
// for each (or the error when the asset is rejected before a manifest can be read).
//
// Every vector follows the published Spec 2.4. Unstructured text is signed with the 2.4
// C2PATextManifestWrapper, which has no padding (see sign_text_2_4), and no vector depends
// on behaviour added in later drafts.
//
// Usage: cargo run --example text_conformance_vectors --features "file_io spec_2_4_text" -- <output dir>

use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use c2pa::{assertions::DataHash, create_signer, Builder, Context, HashRange, Reader, Signer, SigningAlg};
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

fn edit_actions() -> Value {
    json!([
        { "action": "c2pa.opened", "parameters": { "ingredientIds": ["original"] } },
        { "action": "c2pa.edited", "digitalSourceType": HUMAN_WRITTEN }
    ])
}

/// Makes `original` the parentOf ingredient of an edit (first action c2pa.opened).
fn add_original(builder: &mut Builder, format: &str, original: &[u8]) -> Result<()> {
    builder.add_ingredient_from_stream(
        json!({ "title": "original", "relationship": "parentOf", "label": "original" }).to_string(),
        format,
        &mut Cursor::new(original.to_vec()),
    )?;
    Ok(())
}

/// The Spec 2.4 C2PATextManifestWrapper (§A.8.2, §A.8.3): U+FEFF, then the magic, version,
/// length and manifest store, each byte encoded as a variation selector. 2.4 has no padding.
fn wrapper_2_4(store: &[u8]) -> Result<String> {
    let mut framed = b"C2PATXT\0".to_vec();
    framed.push(1);
    framed.extend_from_slice(&u32::try_from(store.len())?.to_be_bytes());
    framed.extend_from_slice(store);
    let mut out = String::from('\u{FEFF}');
    for b in framed {
        let cp = if b <= 15 { 0xFE00 + b as u32 } else { 0xE0100 + (b as u32 - 16) };
        out.push(char::from_u32(cp).context("variation selector")?);
    }
    Ok(out)
}

/// Gives up if the wrapper length and the signed exclusion never agree. Each attempt agrees
/// with a probability of roughly one in six, so this is never reached in practice.
const MAX_SIGNING_ATTEMPTS: usize = 500;

/// Signs unstructured text with a Spec 2.4 wrapper appended after `visible`.
///
/// The exclusion in c2pa.hash.data must cover exactly the wrapper (§A.8.6.1, §A.8.7.3), but
/// the wrapper's UTF-8 length depends on the signed bytes: bytes 0-15 take 3 bytes and the
/// rest take 4. The 2.4 wrapper has no padding to absorb the difference, so this signs with a
/// guessed exclusion length and re-signs with the measured length until the two agree. The
/// data hash covers only `visible`, so it is the same on every attempt.
///
/// `visible` must already be NFC (the vectors use ASCII), since 2.4 measures offsets in the
/// NFC-normalized text.
fn sign_text_2_4(actions: Value, original: Option<(&str, &[u8])>, visible: &str) -> Result<Vec<u8>> {
    let signer = create_signer::from_keys(SIGNCERT, PKEY, SigningAlg::Es256, None)?;
    let start = visible.len() as u64;
    let mut exclusion_len = None;
    for _ in 0..MAX_SIGNING_ATTEMPTS {
        let mut builder = Builder::from_context(Context::new()).with_definition(definition(actions.clone()))?;
        if let Some((format, bytes)) = original {
            add_original(&mut builder, format, bytes)?;
        }
        // "c2pa" yields the raw manifest store, which is wrapped here rather than by a handler
        let placeholder = builder.data_hashed_placeholder(signer.reserve_size(), "c2pa")?;
        let guess = match exclusion_len {
            Some(len) => len,
            None => wrapper_2_4(&placeholder)?.len() as u64,
        };

        let mut dh = DataHash::new("jumbf manifest", "sha256");
        dh.add_exclusion(HashRange::new(start, guess));
        let mut hashed = visible.as_bytes().to_vec();
        hashed.resize((start + guess) as usize, 0);
        dh.gen_hash_from_stream(&mut Cursor::new(hashed))?;

        let store = builder.sign_data_hashed_embeddable(signer.as_ref(), &dh, "c2pa")?;
        let wrapper = wrapper_2_4(&store)?;
        if wrapper.len() as u64 == guess {
            return Ok(format!("{visible}{wrapper}").into_bytes());
        }
        exclusion_len = Some(wrapper.len() as u64);
    }
    anyhow::bail!("the wrapper length did not converge after {MAX_SIGNING_ATTEMPTS} signing attempts")
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
    let txt = sign_text_2_4(created(), None, TXT_DOC)?;
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
    let mut two = txt.clone();
    two.extend_from_slice(&txt[wrapper_start(&txt)..]);
    add("txt-two-wrappers", "txt", "text/plain", "The wrapper is duplicated (manifest.text.multipleWrappers).", two, None);
    let start = wrapper_start(&txt);
    add("txt-truncated-wrapper", "txt", "text/plain", "Partial copy: the wrapper is cut off after its header (manifest.text.corruptedWrapper).", txt[..start + 3 + 40 * 4].to_vec(), None);
    add(
        "txt-edited",
        "txt",
        "text/plain",
        "An edit of txt-valid: first action c2pa.opened with txt-valid as the parentOf ingredient.",
        sign_text_2_4(edit_actions(), Some(("txt", &txt)), "The quick brown fox jumps over the lazy cat.\n")?,
        None,
    );
    let csv = sign_text_2_4(created(), None, CSV_DOC)?;
    add("csv-valid", "csv", "text/csv", "Signed CSV using the unstructured text wrapper.", csv, None);
    // The CSV and TSV sidecar cases (external manifest covering the complete file) are left
    // out: that handling comes from a later draft, not from Spec 2.4.

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
