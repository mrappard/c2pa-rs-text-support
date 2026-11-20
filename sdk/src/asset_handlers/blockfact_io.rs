// Copyright 2026 Adobe. All rights reserved.
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

//! BlockFact `.facti` / `.facta` / `.factv` asset handler, per "Embedding manifests into
//! .facti/.facta/.factv" in the C2PA 2.5 specification and the BlockFact Media File
//! Specification (v2.0).
//!
//! A file is a 4-byte magic, a big-endian `u32` metadata length N, N bytes of JSON metadata
//! (with `format_version` 2 and the media length in `media_length` or `image_length`), the
//! media payload, then a big-endian `u16` extension block count and the blocks, each a
//! 4-byte ASCII type, a big-endian `u32` length L and L bytes of data.
//!
//! The C2PA Manifest Store is the data of the `C2PA` block, with no further framing. The
//! `c2pa.hash.data` exclusion covers exactly that data, not the block's type and length
//! fields. More than one `C2PA` block is treated as no manifest, and other block types are
//! kept as they are.
//!
//! A format version 1 file has no extension blocks: it reads as having no manifest, and
//! writing to it is refused, since adding blocks means rewriting its JSON metadata.

use crate::{
    asset_io::{
        AssetIO, C2paReader, C2paWriter, ObjectLocations, ObjectType, ReadSeek, ReadWriteSeek,
    },
    error::{Error, Result},
    utils::io_utils::{stream_len, ReaderUtils},
};

static SUPPORTED_TYPES: [&str; 6] = [
    "facti",
    "facta",
    "factv",
    "image/vnd.blockfact.facti",
    "audio/vnd.blockfact.facta",
    "video/vnd.blockfact.factv",
];

const MAGICS: [[u8; 4]; 3] = [
    [0xfa, 0x49, 0x41, 0x00], // .facti
    [0xfa, 0x41, 0x41, 0x00], // .facta
    [0xfa, 0x56, 0x41, 0x00], // .factv
];
const C2PA_BLOCK: &[u8; 4] = b"C2PA";

/// Placeholder used to lay out the exclusion before a manifest exists.
const PLACEHOLDER_STORE: &[u8] = b"placeholder manifest";

/// One extension block: `[start, data_start)` is its type and length, `[data_start, end)`
/// its data.
struct Block {
    start: usize,
    data_start: usize,
    end: usize,
    kind: [u8; 4],
}

/// Where the parts of a version 2 file are.
struct Layout {
    /// Offset of the big-endian `u16` block count.
    count_at: usize,
    blocks: Vec<Block>,
}

fn invalid(msg: &str) -> Error {
    Error::InvalidAsset(format!("BlockFact: {msg}"))
}

fn be32(data: &[u8], at: usize) -> Result<usize> {
    let bytes = data
        .get(at..at + 4)
        .ok_or_else(|| invalid("truncated length field"))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
}

/// Parses a file. `Ok(None)` is a format version 1 file, which has no extension blocks.
fn parse(data: &[u8]) -> Result<Option<Layout>> {
    if !data
        .get(..4)
        .is_some_and(|m| MAGICS.iter().any(|magic| m == magic))
    {
        return Err(Error::UnsupportedType);
    }
    let metadata_len = be32(data, 4)?;
    let metadata = data
        .get(8..8 + metadata_len)
        .ok_or_else(|| invalid("truncated JSON metadata"))?;
    let metadata: serde_json::Value =
        serde_json::from_slice(metadata).map_err(|_| invalid("metadata is not JSON"))?;

    let version = metadata.get("format_version").and_then(|v| v.as_u64());
    if version.unwrap_or(1) < 2 {
        return Ok(None);
    }
    let media_len = metadata
        .get("media_length")
        .or_else(|| metadata.get("image_length"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| invalid("metadata has no media_length or image_length"))?
        as usize;

    let count_at = (8 + metadata_len)
        .checked_add(media_len)
        .ok_or_else(|| invalid("media length overflows"))?;
    let count = data
        .get(count_at..count_at + 2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .ok_or_else(|| invalid("truncated extension block count"))?;

    let mut blocks = Vec::with_capacity(count as usize);
    let mut pos = count_at + 2;
    for _ in 0..count {
        let kind: [u8; 4] = data
            .get(pos..pos + 4)
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| invalid("truncated extension block"))?;
        let len = be32(data, pos + 4)?;
        let data_start = pos + 8;
        let end = data_start
            .checked_add(len)
            .filter(|&end| end <= data.len())
            .ok_or_else(|| invalid("truncated extension block"))?;
        blocks.push(Block {
            start: pos,
            data_start,
            end,
            kind,
        });
        pos = end;
    }
    Ok(Some(Layout { count_at, blocks }))
}

fn c2pa_blocks(layout: &Layout) -> Vec<&Block> {
    layout
        .blocks
        .iter()
        .filter(|b| &b.kind == C2PA_BLOCK)
        .collect()
}

fn block_bytes(store_bytes: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(store_bytes.len())
        .map_err(|_| invalid("manifest store is too large for a block"))?;
    let mut out = Vec::with_capacity(8 + store_bytes.len());
    out.extend_from_slice(C2PA_BLOCK);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(store_bytes);
    Ok(out)
}

/// Returns `data` with `store_bytes` as its one `C2PA` block, replacing an existing one in
/// place or appending a new one, and the byte range of the block's data.
fn embed(data: &[u8], store_bytes: &[u8]) -> Result<(Vec<u8>, (usize, usize))> {
    let layout = parse(data)?.ok_or_else(|| {
        invalid("format version 1 files have no extension blocks; upgrade the file to version 2")
    })?;
    let block = block_bytes(store_bytes)?;

    match c2pa_blocks(&layout)[..] {
        [existing] => {
            let mut out = Vec::with_capacity(data.len() + store_bytes.len());
            out.extend_from_slice(&data[..existing.start]);
            out.extend_from_slice(&block);
            out.extend_from_slice(&data[existing.end..]);
            let start = existing.start + 8;
            Ok((out, (start, store_bytes.len())))
        }
        [] => {
            let count = layout.blocks.len() + 1;
            let count = u16::try_from(count).map_err(|_| invalid("too many extension blocks"))?;
            let mut out = data.to_vec();
            out[layout.count_at..layout.count_at + 2].copy_from_slice(&count.to_be_bytes());
            let start = out.len() + 8;
            out.extend_from_slice(&block);
            Ok((out, (start, store_bytes.len())))
        }
        _ => Err(invalid("more than one C2PA block")),
    }
}

fn read_all(mut input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
    input_stream.rewind()?;
    let len = stream_len(input_stream)?;
    input_stream.read_to_vec(len)
}

pub struct BlockFactIO {}

impl C2paReader for BlockFactIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let data = read_all(input_stream)?;
        let layout = parse(&data)?.ok_or(Error::JumbfNotFound)?;
        // More than one C2PA block is treated as no manifest.
        match c2pa_blocks(&layout)[..] {
            [block] if block.end > block.data_start => {
                Ok(data[block.data_start..block.end].to_vec())
            }
            _ => Err(Error::JumbfNotFound),
        }
    }

    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl C2paWriter for BlockFactIO {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let data = read_all(input_stream)?;
        let (out, _) = embed(&data, store_bytes)?;
        output_stream.rewind()?;
        output_stream.write_all(&out)?;
        Ok(())
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let data = read_all(input_stream)?;
        let layout = parse(&data)?.ok_or_else(|| invalid("format version 1 file"))?;
        let (full_len, (start, len)) = match c2pa_blocks(&layout)[..] {
            [block] => (data.len(), (block.data_start, block.end - block.data_start)),
            [] => {
                // No manifest yet: lay out the exclusion with a placeholder.
                let (out, range) = embed(&data, PLACEHOLDER_STORE)?;
                (out.len(), range)
            }
            _ => return Err(invalid("more than one C2PA block")),
        };
        let end = start + len;
        Ok(vec![
            ObjectLocations {
                offset: start as u64,
                length: len as u64,
                htype: ObjectType::C2pa,
            },
            ObjectLocations {
                offset: 0,
                length: start as u64,
                htype: ObjectType::Other,
            },
            ObjectLocations {
                offset: end as u64,
                length: full_len.saturating_sub(end) as u64,
                htype: ObjectType::Other,
            },
        ])
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        let data = read_all(input_stream)?;
        let mut out = data.clone();
        if let Some(layout) = parse(&data)? {
            let c2pa = c2pa_blocks(&layout);
            if !c2pa.is_empty() {
                let count = (layout.blocks.len() - c2pa.len()) as u16;
                out = data[..layout.count_at].to_vec();
                out.extend_from_slice(&count.to_be_bytes());
                for block in layout.blocks.iter().filter(|b| &b.kind != C2PA_BLOCK) {
                    out.extend_from_slice(&data[block.start..block.end]);
                }
            }
        }
        output_stream.rewind()?;
        output_stream.write_all(&out)?;
        Ok(())
    }
}

impl AssetIO for BlockFactIO {
    fn new(_asset_type: &str) -> Self {
        BlockFactIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(BlockFactIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(BlockFactIO::new(asset_type)))
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    // Each extension has its own IANA media type, so the default single-MIME derivation
    // from `supported_types()` doesn't apply.
    fn mime_type_map(&self) -> Vec<(String, String)> {
        [
            ("facti", "image/vnd.blockfact.facti"),
            ("facta", "audio/vnd.blockfact.facta"),
            ("factv", "video/vnd.blockfact.factv"),
        ]
        .into_iter()
        .map(|(ext, mime)| (ext.to_string(), mime.to_string()))
        .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    /// A version 2 `.facti` wrapping `media`, with the given extension blocks.
    fn facti(media: &[u8], blocks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let metadata = format!(
            r#"{{"format_version":2,"image_length":{},"mime":"image/png"}}"#,
            media.len()
        );
        let mut out = MAGICS[0].to_vec();
        out.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
        out.extend_from_slice(metadata.as_bytes());
        out.extend_from_slice(media);
        out.extend_from_slice(&(blocks.len() as u16).to_be_bytes());
        for (kind, data) in blocks {
            out.extend_from_slice(*kind);
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    fn write(source: &[u8], store: &[u8]) -> Result<Vec<u8>> {
        let mut output = Cursor::new(Vec::new());
        BlockFactIO {}.write_c2pa(&mut Cursor::new(source.to_vec()), &mut output, store)?;
        Ok(output.into_inner())
    }

    fn read(data: &[u8]) -> Result<Vec<u8>> {
        BlockFactIO {}.read_c2pa(&mut Cursor::new(data.to_vec()))
    }

    fn c2pa_location(data: &[u8]) -> ObjectLocations {
        BlockFactIO {}
            .get_object_locations(&mut Cursor::new(data.to_vec()))
            .unwrap()
            .into_iter()
            .find(|l| l.htype == ObjectType::C2pa)
            .unwrap()
    }

    const MEDIA: &[u8] = b"\x89PNG\r\n\x1a\n fake media payload";

    #[test]
    fn appends_a_c2pa_block_and_round_trips() {
        let source = facti(MEDIA, &[(b"ZKPF", b"proof")]);
        let out = write(&source, b"store bytes").unwrap();
        assert_eq!(read(&out).unwrap(), b"store bytes");
        assert_eq!(
            out,
            facti(MEDIA, &[(b"ZKPF", b"proof"), (b"C2PA", b"store bytes")])
        );
    }

    #[test]
    fn exclusion_is_exactly_the_block_data() {
        let out = write(&facti(MEDIA, &[]), b"store bytes").unwrap();
        let loc = c2pa_location(&out);
        assert_eq!(
            &out[loc.offset as usize..(loc.offset + loc.length) as usize],
            b"store bytes"
        );
        // The block's type and length fields stay hashed.
        assert_eq!(
            &out[loc.offset as usize - 8..loc.offset as usize - 4],
            b"C2PA"
        );
    }

    #[test]
    fn placeholder_layout_matches_the_written_layout() {
        let source = facti(MEDIA, &[]);
        let before = c2pa_location(&source);
        let after = c2pa_location(&write(&source, &vec![3u8; PLACEHOLDER_STORE.len()]).unwrap());
        assert_eq!((before.offset, before.length), (after.offset, after.length));
    }

    #[test]
    fn replaces_in_place_and_keeps_other_blocks() {
        let source = facti(MEDIA, &[(b"C2PA", b"first"), (b"WMRK", b"mark")]);
        let out = write(&source, b"second!").unwrap();
        assert_eq!(
            out,
            facti(MEDIA, &[(b"C2PA", b"second!"), (b"WMRK", b"mark")])
        );
        assert_eq!(read(&out).unwrap(), b"second!");
    }

    #[test]
    fn media_length_and_audio_video_magics_work() {
        for magic in &MAGICS[1..] {
            let metadata = format!(r#"{{"format_version":2,"media_length":{}}}"#, MEDIA.len());
            let mut source = magic.to_vec();
            source.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
            source.extend_from_slice(metadata.as_bytes());
            source.extend_from_slice(MEDIA);
            source.extend_from_slice(&0u16.to_be_bytes());
            let out = write(&source, b"store").unwrap();
            assert_eq!(read(&out).unwrap(), b"store");
        }
    }

    #[test]
    fn two_c2pa_blocks_are_treated_as_no_manifest() {
        let doubled = facti(MEDIA, &[(b"C2PA", b"one"), (b"C2PA", b"two")]);
        assert!(matches!(read(&doubled), Err(Error::JumbfNotFound)));
        assert!(write(&doubled, b"x").is_err());
    }

    #[test]
    fn version_1_reads_as_no_manifest_and_is_not_written() {
        let metadata = br#"{"image_length":24}"#;
        let mut v1 = MAGICS[0].to_vec();
        v1.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
        v1.extend_from_slice(metadata);
        v1.extend_from_slice(MEDIA);
        assert!(matches!(read(&v1), Err(Error::JumbfNotFound)));
        assert!(write(&v1, b"x").is_err());
    }

    #[test]
    fn remove_drops_only_the_c2pa_block() {
        let source = facti(MEDIA, &[(b"ZKPF", b"proof")]);
        let out = write(&source, b"store").unwrap();
        let mut output = Cursor::new(Vec::new());
        BlockFactIO {}
            .remove_c2pa(&mut Cursor::new(out), &mut output)
            .unwrap();
        assert_eq!(output.into_inner(), source);
    }

    #[test]
    fn truncated_and_foreign_files_are_rejected() {
        let out = write(&facti(MEDIA, &[]), b"store").unwrap();
        assert!(read(&out[..out.len() - 2]).is_err());
        assert!(matches!(
            read(b"\x89PNG\r\n\x1a\n"),
            Err(Error::UnsupportedType)
        ));
    }
}
