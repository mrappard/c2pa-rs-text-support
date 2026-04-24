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

static SUPPORTED_TYPES: [&str; 20] = [
    "txt", "md", "markdown", "py", "js", "ts", "yaml", "yml", "toml", "sql", "rs", "sh", "rb", "c",
    "cpp", "h", "hpp", "cs", "go", "php",
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

struct ManifestInfo {
    decoded_manifest: Option<Vec<u8>>,
    start: usize,
    length: usize,
    #[allow(dead_code)]
    reference: String,
}

fn detect_manifest_location(reader: &mut dyn CAIRead) -> Result<Option<ManifestInfo>> {
    reader.rewind()?;
    let mut content = Vec::new();
    reader.read_to_end(&mut content)?;

    let begin_pattern = BEGIN_MANIFEST.as_bytes();
    let end_pattern = END_MANIFEST.as_bytes();

    if let Some(begin_idx) = content.windows(begin_pattern.len()).position(|w| w == begin_pattern) {
        if let Some(end_idx_rel) = content[begin_idx..].windows(end_pattern.len()).position(|w| w == end_pattern) {
            let end_idx = begin_idx + end_idx_rel;
            let end_idx_full = end_idx + end_pattern.len();

            // Found delimiters. Now find the block boundaries (line-based).
            let mut block_start = begin_idx;
            while block_start > 0 && content[block_start - 1] != b'\n' && content[block_start - 1] != b'\r' {
                block_start -= 1;
            }
            
            let mut block_end = end_idx_full;
            while block_end < content.len() && content[block_end] != b'\n' && content[block_end] != b'\r' {
                block_end += 1;
            }
            
            // Include trailing newline if it exists
            if block_end < content.len() && content[block_end] == b'\r' {
                block_end += 1;
            }
            if block_end < content.len() && content[block_end] == b'\n' {
                block_end += 1;
            }

            let reference_bytes = &content[begin_idx + begin_pattern.len() .. end_idx];
            let reference = String::from_utf8_lossy(reference_bytes).trim().to_string();
            
            let decoded_manifest = if reference.starts_with(DATA_URI_PREFIX) {
                let b64 = &reference[DATA_URI_PREFIX.len()..];
                Some(base64::decode(b64).map_err(|_| Error::InvalidAsset("Invalid base64 in manifest block".to_string()))?)
            } else {
                None
            };

            return Ok(Some(ManifestInfo {
                decoded_manifest,
                start: block_start,
                length: block_end - block_start,
                reference,
            }));
        }
    }
    Ok(None)
}

fn get_comment_syntax(asset_type: &str) -> (&str, &str) {
    match asset_type.to_lowercase().as_str() {
        "py" | "yaml" | "yml" | "toml" | "rb" | "sh" | "pl" => ("# ", ""),
        "js" | "ts" | "rs" | "c" | "cpp" | "h" | "hpp" | "cs" | "go" | "php" => ("// ", ""),
        "sql" | "hs" | "lua" => ("-- ", ""),
        "css" => ("/* ", " */"),
        "md" | "markdown" | "html" | "xml" => ("<!-- ", " -->"),
        _ => ("# ", ""), // default to #
    }
}

fn create_manifest_block(asset_type: &str, data: &[u8]) -> String {
    let b64 = base64::encode(data);
    let reference = format!("{}{}", DATA_URI_PREFIX, b64);
    let (prefix, suffix) = get_comment_syntax(asset_type);
    format!("{}{} {} {}{}\n", prefix, BEGIN_MANIFEST, reference, END_MANIFEST, suffix)
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
            // Replace existing block
            output_stream.write_all(&content[..info.start])?;
            output_stream.write_all(new_block.as_bytes())?;
            output_stream.write_all(&content[info.start + info.length..])?;
        } else {
            // Add at beginning
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

        // The manifest block is the CAI block
        positions.push(HashObjectPositions {
            offset: info.start,
            length: info.length,
            htype: HashBlockObjectType::Cai,
        });

        // Other parts of the file
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

                let (prefix, suffix) = get_comment_syntax(&self.asset_type);
                let new_block = format!("{}{} {} {}{}\n", prefix, BEGIN_MANIFEST, url, END_MANIFEST, suffix);

                if let Some(info) = info {
                    output_stream.write_all(&content[..info.start])?;
                    output_stream.write_all(new_block.as_bytes())?;
                    output_stream.write_all(&content[info.start + info.length..])?;
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
        assert!(content.contains(BEGIN_MANIFEST));
        assert!(content.contains(END_MANIFEST));
        assert!(content.contains("# "));
    }

    #[test]
    fn test_structured_text_multi_line() {
        let data = b"test manifest data multi";
        let asset_type = "md";
        let io = StructuredTextIdIO::new(asset_type);
        
        let temp_dir = tempdirectory().unwrap();
        let path = temp_dir_path(&temp_dir, "test.md");
        
        // Manually insert a multi-line manifest
        let b64 = base64::encode(data);
        let multi_line = format!("---\ntitle: test\n{}\n{}{}\n{}\n---\nbody\n", BEGIN_MANIFEST, DATA_URI_PREFIX, b64, END_MANIFEST);
        fs::write(&path, multi_line).unwrap();
        
        let read_data = io.read_cai_store(&path).unwrap();
        assert_eq!(data, read_data.as_slice());
    }
}
