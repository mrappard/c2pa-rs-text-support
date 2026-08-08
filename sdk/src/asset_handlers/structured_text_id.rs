// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use std::{
    fs::{self, File, OpenOptions},
    io::{Cursor, Seek, SeekFrom, Write},
    path::Path,
};

use crate::crypto::base64;
use crate::{
    asset_io::{
        rename_or_move, AssetIO, AssetPatch, CAIRead, CAIReadWrite, CAIReader, CAIWriter,
        HashBlockObjectType, HashObjectPositions, RemoteRefEmbed, RemoteRefEmbedType,
    },
    error::{Error, Result},
    utils::io_utils::{stream_len, tempfile_builder},
};

const BEGIN_MANIFEST: &str = "-----BEGIN C2PA MANIFEST-----";
const END_MANIFEST: &str = "-----END C2PA MANIFEST-----";
const DATA_URI_PREFIX: &str = "data:application/c2pa;base64,";

static SUPPORTED_TYPES: [&str; 22] = [
    "txt", "md", "markdown", "py", "js", "ts", "jsonc", "yaml", "yml", "toml", "sql", "rs", "sh", "rb", "c",
    "cpp", "h", "hpp", "cs", "go", "php", "xml",
];

pub struct StructuredTextIdIO {
    asset_type: String,
}

impl StructuredTextIdIO {
    pub fn new(asset_type: &str) -> Self {
        StructuredTextIdIO {
            asset_type: asset_type.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct ManifestInfo {
    decoded_manifest: Option<Vec<u8>>,
    start: usize,
    length: usize,
    reference: String,
}

fn structured_text_error(message: impl Into<String>) -> Error {
    Error::InvalidAsset(message.into())
}

fn has_bare_cr_line_endings(content: &[u8]) -> bool {
    content
        .iter()
        .enumerate()
        .any(|(i, b)| *b == b'\r' && content.get(i + 1) != Some(&b'\n'))
}

fn line_start(content: &[u8], idx: usize) -> usize {
    let mut start = idx;
    while start > 0 && content[start - 1] != b'\n' {
        start -= 1;
    }
    start
}

fn line_end_including_terminator(content: &[u8], idx: usize) -> usize {
    let mut end = idx;
    while end < content.len() && content[end] != b'\n' {
        end += 1;
    }
    if end < content.len() {
        end += 1;
    }
    end
}

fn line_before_offset(content: &[u8], idx: usize) -> Option<(usize, usize)> {
    if idx == 0 {
        return None;
    }

    let end_exclusive = idx;
    let mut start = idx;
    while start > 0 && content[start - 1] != b'\n' {
        start -= 1;
    }

    Some((start, end_exclusive))
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();

    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }

    &bytes[start..end]
}

fn is_front_matter_manifest(content: &[u8], begin_idx: usize, end_idx: usize) -> bool {
    let Some((begin_line_start, _)) = line_before_offset(content, begin_idx) else {
        return false;
    };
    let Some((previous_line_start, previous_line_end)) = line_before_offset(content, begin_line_start.saturating_sub(1)) else {
        return false;
    };

    let previous_line = trim_ascii_whitespace(&content[previous_line_start..previous_line_end]);
    if previous_line != b"---" && previous_line != b"+++" {
        return false;
    }

    let end_line_end = line_end_including_terminator(content, end_idx);
    let next_line_start = end_line_end;
    if next_line_start >= content.len() {
        return false;
    }
    let next_line_end = line_end_including_terminator(content, next_line_start);
    let next_line = trim_ascii_whitespace(&content[next_line_start..next_line_end]);

    next_line == b"---" || next_line == b"+++" || !next_line.is_empty()
}

fn find_manifest_blocks(content: &[u8]) -> Vec<(usize, usize)> {
    let begin_pattern = BEGIN_MANIFEST.as_bytes();
    let end_pattern = END_MANIFEST.as_bytes();
    let mut blocks = Vec::new();
    let mut search_from = 0;

    while search_from <= content.len().saturating_sub(begin_pattern.len()) {
        let Some(begin_rel) = content[search_from..]
            .windows(begin_pattern.len())
            .position(|w| w == begin_pattern)
        else {
            break;
        };
        let begin_idx = search_from + begin_rel;

        if let Some(end_rel) = content[begin_idx..]
            .windows(end_pattern.len())
            .position(|w| w == end_pattern)
        {
            let end_idx = begin_idx + end_rel;
            let end_idx_full = end_idx + end_pattern.len();
            blocks.push((begin_idx, end_idx_full));
            search_from = end_idx_full;
        } else {
            // A begin delimiter without a matching end delimiter is still an invalid manifest block.
            blocks.push((begin_idx, content.len()));
            break;
        }
    }

    blocks
}

fn extract_reference(content: &[u8], begin_idx: usize, end_idx_full: usize) -> Result<String> {
    let begin_pattern = BEGIN_MANIFEST.as_bytes();
    let end_pattern = END_MANIFEST.as_bytes();
    let end_idx = end_idx_full
        .checked_sub(end_pattern.len())
        .ok_or_else(|| structured_text_error("manifest.structuredText.noManifest"))?;

    let reference_bytes = &content[begin_idx + begin_pattern.len()..end_idx];
    let reference = String::from_utf8_lossy(reference_bytes).trim().to_string();

    if reference.is_empty() {
        return Err(structured_text_error("manifest.structuredText.emptyReference"));
    }

    Ok(reference)
}

fn decode_manifest_reference(reference: &str) -> Result<Option<Vec<u8>>> {
    if let Some(b64) = reference.strip_prefix(DATA_URI_PREFIX) {
        return base64::decode(b64)
            .map(Some)
            .map_err(|_| structured_text_error("Invalid base64 in manifest block"));
    }

    // External references are valid manifest references, but this handler does not fetch them.
    Ok(None)
}

fn detect_manifest_location(reader: &mut dyn CAIRead) -> Result<Option<ManifestInfo>> {
    reader.rewind()?;
    let mut content = Vec::new();
    reader.read_to_end(&mut content)?;

    if has_bare_cr_line_endings(&content) {
        return Err(structured_text_error(
            "manifest.structuredText.unsupportedBareCrLineEndings",
        ));
    }

    let begin_pattern = BEGIN_MANIFEST.as_bytes();
    let end_pattern = END_MANIFEST.as_bytes();
    let blocks = find_manifest_blocks(&content);

    if blocks.is_empty() {
        let has_begin = content.windows(begin_pattern.len()).any(|w| w == begin_pattern);
        let has_end = content.windows(end_pattern.len()).any(|w| w == end_pattern);
        if has_begin || has_end {
            return Err(structured_text_error("manifest.structuredText.noManifest"));
        }
        return Ok(None);
    }

    if blocks.len() > 1 {
        return Err(structured_text_error(
            "manifest.structuredText.multipleReferences",
        ));
    }

    let (begin_idx, end_idx_full) = blocks[0];

    if end_idx_full == content.len() && !content[begin_idx..].windows(end_pattern.len()).any(|w| w == end_pattern) {
        return Err(structured_text_error("manifest.structuredText.noManifest"));
    }

    let block_start = line_start(&content, begin_idx);
    let mut block_end = line_end_including_terminator(&content, end_idx_full);

    if is_front_matter_manifest(&content, begin_idx, end_idx_full) {
        block_end = line_end_including_terminator(&content, end_idx_full);
    }

    let reference = extract_reference(&content, begin_idx, end_idx_full)?;
    let decoded_manifest = decode_manifest_reference(&reference)?;

    Ok(Some(ManifestInfo {
        decoded_manifest,
        start: block_start,
        length: block_end - block_start,
        reference,
    }))
}

fn get_comment_syntax(asset_type: &str) -> (&str, &str) {
    match asset_type.to_lowercase().as_str() {
        "py" | "yaml" | "yml" | "toml" | "rb" | "sh" | "pl" => ("# ", ""),
        "js" | "ts" | "jsonc" | "rs" | "c" | "cpp" | "h" | "hpp" | "cs" | "go" | "php" => ("// ", ""),
        "sql" | "hs" | "lua" => ("-- ", ""),
        "css" => ("/* ", " */"),
        "md" | "markdown" | "html" | "xml" => ("<!-- ", " -->"),
        _ => ("# ", ""), // default to #
    }
}

fn create_manifest_block(asset_type: &str, data: &[u8]) -> String {
    let b64 = base64::encode(data);
    let reference = format!("{}{}", DATA_URI_PREFIX, b64);
    create_manifest_reference_block(asset_type, &reference)
}

fn create_manifest_reference_block(asset_type: &str, reference: &str) -> String {
    let (prefix, suffix) = get_comment_syntax(asset_type);
    format!("{}{} {} {}{}\n", prefix, BEGIN_MANIFEST, reference, END_MANIFEST, suffix)
}

fn starts_with_reserved_first_line(content: &[u8]) -> bool {
    content.starts_with(b"#!") || content.starts_with(b"<?xml")
}

fn append_manifest_block(content: &[u8], block: &[u8], output_stream: &mut dyn CAIReadWrite) -> Result<()> {
    output_stream.write_all(content)?;
    if !content.is_empty() && !content.ends_with(b"\n") {
        output_stream.write_all(b"\n")?;
    }
    output_stream.write_all(block)?;
    Ok(())
}

impl CAIReader for StructuredTextIdIO {
    fn read_cai(&self, reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        match detect_manifest_location(reader)? {
            Some(info) => info.decoded_manifest.ok_or(Error::JumbfNotFound),
            None => Err(Error::JumbfNotFound),
        }
    }

    fn read_xmp(&self, _asset_reader: &mut dyn CAIRead) -> Option<String> {
        None
    }
}

impl AssetIO for StructuredTextIdIO {
    fn new(asset_type: &str) -> Self {
        StructuredTextIdIO::new(asset_type)
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(StructuredTextIdIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(StructuredTextIdIO::new(asset_type)))
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut input_stream = OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        let mut temp_file = tempfile_builder("c2pa_temp")?;

        self.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;

        rename_or_move(temp_file, asset_path)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut input_stream = File::open(asset_path).map_err(|_| Error::EmbeddingError)?;
        self.get_object_locations_from_stream(&mut input_stream)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        let mut input_file = File::open(asset_path)?;
        let mut temp_file = tempfile_builder("c2pa_temp")?;
        self.remove_cai_store_from_stream(&mut input_file, &mut temp_file)?;
        rename_or_move(temp_file, asset_path)
    }

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

impl CAIWriter for StructuredTextIdIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        input_stream.rewind()?;
        let info = detect_manifest_location(input_stream)?;
        input_stream.rewind()?;

        let mut content = Vec::new();
        input_stream.read_to_end(&mut content)?;

        let new_block = create_manifest_block(&self.asset_type, store_bytes);

        if let Some(info) = info {
            // Replace existing block.
            output_stream.write_all(&content[..info.start])?;
            output_stream.write_all(new_block.as_bytes())?;
            output_stream.write_all(&content[info.start + info.length..])?;
        } else if starts_with_reserved_first_line(&content) {
            // Preserve shebang/XML-declaration semantics by placing the manifest block at the end.
            append_manifest_block(&content, new_block.as_bytes(), output_stream)?;
        } else {
            // Add at beginning.
            output_stream.write_all(new_block.as_bytes())?;
            output_stream.write_all(&content)?;
        }

        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        input_stream.rewind()?;
        let info = detect_manifest_location(input_stream)?.ok_or(Error::JumbfNotFound)?;

        let mut positions = Vec::new();

        positions.push(HashObjectPositions {
            offset: info.start,
            length: info.length,
            htype: HashBlockObjectType::Cai,
        });

        if info.start > 0 {
            positions.push(HashObjectPositions {
                offset: 0,
                length: info.start,
                htype: HashBlockObjectType::Other,
            });
        }

        let end = info.start + info.length;
        let total_len = stream_len(input_stream)? as usize;
        if end < total_len {
            positions.push(HashObjectPositions {
                offset: end,
                length: total_len - end,
                htype: HashBlockObjectType::Other,
            });
        }

        Ok(positions)
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        input_stream.rewind()?;
        let info = detect_manifest_location(input_stream)?;
        input_stream.rewind()?;

        let mut content = Vec::new();
        input_stream.read_to_end(&mut content)?;

        if let Some(info) = info {
            output_stream.write_all(&content[..info.start])?;
            output_stream.write_all(&content[info.start + info.length..])?;
        } else {
            output_stream.write_all(&content)?;
        }

        Ok(())
    }
}

impl AssetPatch for StructuredTextIdIO {
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(asset_path)?;

        let info = detect_manifest_location(&mut f)?.ok_or(Error::JumbfNotFound)?;
        
        let new_block = create_manifest_block(&self.asset_type, store_bytes);
        
        if new_block.len() == info.length {
            f.seek(SeekFrom::Start(info.start as u64))?;
            f.write_all(new_block.as_bytes())?;
            Ok(())
        } else {
            Err(Error::InvalidAsset("patch_cai_store size mismatch".to_string()))
        }
    }
}

impl RemoteRefEmbed for StructuredTextIdIO {
    fn embed_reference(&self, asset_path: &Path, embed_ref: RemoteRefEmbedType) -> Result<()> {
        let mut input_stream = File::open(asset_path)?;
        let mut output_stream = Cursor::new(Vec::new());
        self.embed_reference_to_stream(&mut input_stream, &mut output_stream, embed_ref)?;
        fs::write(asset_path, output_stream.into_inner())?;
        Ok(())
    }

    fn embed_reference_to_stream(
        &self,
        source_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
        match embed_ref {
            RemoteRefEmbedType::Xmp(url) => {
                source_stream.rewind()?;
                let info = detect_manifest_location(source_stream)?;
                source_stream.rewind()?;
                
                let mut content = Vec::new();
                source_stream.read_to_end(&mut content)?;

                let new_block = create_manifest_reference_block(&self.asset_type, &url);

                if let Some(info) = info {
                    output_stream.write_all(&content[..info.start])?;
                    output_stream.write_all(new_block.as_bytes())?;
                    output_stream.write_all(&content[info.start + info.length..])?;
                } else if starts_with_reserved_first_line(&content) {
                    append_manifest_block(&content, new_block.as_bytes(), output_stream)?;
                } else {
                    output_stream.write_all(new_block.as_bytes())?;
                    output_stream.write_all(&content)?;
                }
                Ok(())
            }
            _ => Err(Error::UnsupportedType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::io_utils::tempdirectory;
    use crate::utils::test::temp_dir_path;

    fn data_uri_block(asset_type: &str, data: &[u8]) -> String {
        create_manifest_block(asset_type, data)
    }

    fn assert_err_contains<T>(result: Result<T>, expected: &str) {
        let err = result.expect_err("expected error");
        assert!(
            format!("{err:?}").contains(expected),
            "expected error containing {expected:?}, got {err:?}"
        );
    }

    #[test]
    fn test_structured_text_roundtrip() {
        let data = b"test manifest data";
        let asset_type = "py";
        let io = StructuredTextIdIO::new(asset_type);
        
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.py");
        fs::write(&path, "print('hello')\n").unwrap();
        
        io.save_cai_store(&path, data).unwrap();
        
        let read_data = io.read_cai_store(&path).unwrap();
        assert_eq!(data, read_data.as_slice());
        
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("# -----BEGIN C2PA MANIFEST-----"));
        assert!(content.contains(END_MANIFEST));
        assert!(content.ends_with("print('hello')\n"));
    }

    #[test]
    fn test_structured_text_multi_line_front_matter_read() {
        let data = b"test manifest data multi";
        let asset_type = "md";
        let io = StructuredTextIdIO::new(asset_type);
        
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.md");
        
        let b64 = base64::encode(data);
        let multi_line = format!(
            "---\ntitle: test\n{}\n{}{}\n{}\n---\nbody\n",
            BEGIN_MANIFEST, DATA_URI_PREFIX, b64, END_MANIFEST
        );
        fs::write(&path, multi_line).unwrap();
        
        let read_data = io.read_cai_store(&path).unwrap();
        assert_eq!(data, read_data.as_slice());
    }

    #[test]
    fn test_replaces_existing_manifest_block() {
        let io = StructuredTextIdIO::new("rs");
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.rs");
        fs::write(&path, format!("{}fn main() {{}}\n", data_uri_block("rs", b"old"))).unwrap();

        io.save_cai_store(&path, b"new").unwrap();

        let read_data = io.read_cai_store(&path).unwrap();
        assert_eq!(b"new", read_data.as_slice());

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.matches(BEGIN_MANIFEST).count(), 1);
        assert!(content.ends_with("fn main() {}\n"));
    }

    #[test]
    fn test_multiple_manifest_blocks_rejected() {
        let io = StructuredTextIdIO::new("py");
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.py");
        let content = format!(
            "{}print('middle')\n{}",
            data_uri_block("py", b"one"),
            data_uri_block("py", b"two")
        );
        fs::write(&path, content).unwrap();

        assert_err_contains(io.read_cai_store(&path), "multipleReferences");
    }

    #[test]
    fn test_empty_manifest_reference_rejected() {
        let io = StructuredTextIdIO::new("py");
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.py");
        fs::write(
            &path,
            format!("# {}    {}\nprint('hello')\n", BEGIN_MANIFEST, END_MANIFEST),
        )
        .unwrap();

        assert_err_contains(io.read_cai_store(&path), "emptyReference");
    }

    #[test]
    fn test_missing_end_manifest_rejected() {
        let io = StructuredTextIdIO::new("py");
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.py");
        fs::write(&path, format!("# {} data:application/c2pa;base64,abc\n", BEGIN_MANIFEST)).unwrap();

        assert_err_contains(io.read_cai_store(&path), "noManifest");
    }

    #[test]
    fn test_bare_cr_line_endings_rejected() {
        let io = StructuredTextIdIO::new("py");
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.py");
        let content = data_uri_block("py", b"data").replace('\n', "\r");
        fs::write(&path, content).unwrap();

        assert_err_contains(io.read_cai_store(&path), "unsupportedBareCrLineEndings");
    }

    #[test]
    fn test_crlf_line_endings_supported_and_preserved_for_existing_content() {
        let io = StructuredTextIdIO::new("py");
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.py");
        fs::write(&path, "print('hello')\r\n").unwrap();

        io.save_cai_store(&path, b"data").unwrap();

        let content = fs::read(&path).unwrap();
        assert!(content.ends_with(b"print('hello')\r\n"));
        assert_eq!(io.read_cai_store(&path).unwrap(), b"data");
    }

    #[test]
    fn test_shebang_file_places_manifest_at_end() {
        let io = StructuredTextIdIO::new("sh");
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.sh");
        fs::write(&path, "#!/usr/bin/env bash\necho hello\n").unwrap();

        io.save_cai_store(&path, b"data").unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("#!/usr/bin/env bash\n"));
        assert!(content.trim_end().ends_with(END_MANIFEST));
        assert_eq!(io.read_cai_store(&path).unwrap(), b"data");
    }

    #[test]
    fn test_xml_declaration_places_manifest_at_end() {
        let io = StructuredTextIdIO::new("xml");
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.xml");
        fs::write(&path, "<?xml version=\"1.0\"?>\n<root/>\n").unwrap();

        io.save_cai_store(&path, b"data").unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("<?xml version=\"1.0\"?>\n"));
        assert!(content.contains("<!-- -----BEGIN C2PA MANIFEST-----"));
        assert!(content.trim_end().ends_with("-->"));
        assert_eq!(io.read_cai_store(&path).unwrap(), b"data");
    }

    #[test]
    fn test_remote_reference_embedded_but_not_read_as_cai_store() {
        let io = StructuredTextIdIO::new("js");
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.js");
        fs::write(&path, "console.log('hello');\n").unwrap();

        io.embed_reference(&path, RemoteRefEmbedType::Xmp("https://example.com/a.c2pa".to_string()))
            .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("// -----BEGIN C2PA MANIFEST----- https://example.com/a.c2pa"));
        assert!(content.contains(END_MANIFEST));
        assert!(io.read_cai_store(&path).is_err());
    }

    #[test]
    fn test_jsonc_roundtrip_uses_line_comment() {
        let data = b"jsonc manifest data";
        let io = StructuredTextIdIO::new("jsonc");

        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "settings.jsonc");
        fs::write(
            &path,
            "{\n  // existing JSONC comment\n  \"enabled\": true,\n}\n",
        )
        .unwrap();

        io.save_cai_store(&path, data).unwrap();

        let read_data = io.read_cai_store(&path).unwrap();
        assert_eq!(data, read_data.as_slice());

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("// -----BEGIN C2PA MANIFEST-----"));
        assert!(content.contains("\n{\n  // existing JSONC comment\n"));
    }

    #[test]
    fn test_jsonc_remote_reference_uses_line_comment() {
        let io = StructuredTextIdIO::new("jsonc");
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "settings.jsonc");
        fs::write(&path, "{\n  \"enabled\": true\n}\n").unwrap();

        io.embed_reference(
            &path,
            RemoteRefEmbedType::Xmp("https://example.com/settings.c2pa".to_string()),
        )
        .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("// -----BEGIN C2PA MANIFEST----- https://example.com/settings.c2pa"));
        assert!(content.ends_with("{\n  \"enabled\": true\n}\n"));
    }

    #[test]
    fn test_remove_manifest_store() {
        let io = StructuredTextIdIO::new("py");
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.py");
        fs::write(&path, "print('hello')\n").unwrap();

        io.save_cai_store(&path, b"data").unwrap();
        io.remove_cai_store(&path).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "print('hello')\n");
    }

    #[test]
    fn test_object_locations_exclude_manifest_block() {
        let io = StructuredTextIdIO::new("py");
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.py");
        fs::write(&path, "print('hello')\n").unwrap();

        io.save_cai_store(&path, b"data").unwrap();
        let positions = io.get_object_locations(&path).unwrap();

        assert!(positions.iter().any(|p| matches!(p.htype, HashBlockObjectType::Cai)));
        assert!(positions.iter().any(|p| matches!(p.htype, HashBlockObjectType::Other)));
    }
}
