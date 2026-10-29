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

//! Ogg (RFC 3533) asset handler, per "Embedding manifests into OGG Vorbis" in the C2PA 2.5
//! specification: the C2PA Manifest Store is carried in its own logical bitstream, whose
//! first packet is the 5-byte identifier `\x00c2pa` followed by the Manifest Store.
//!
//! The hard binding is the General Box Hash (`c2pa.hash.boxes`) as its "Ogg-specific
//! Handling" defines it: each logical bitstream is one box, made of every page with its
//! serial number, in order, named `Stream-[serial]` (the serial read as a little-endian
//! unsigned 32-bit integer), and the C2PA stream is the `C2PA` box. A stream whose pages are
//! interleaved with other streams' pages is a segmented box.
//!
//! The specification leaves the rest open (see c2pa-org/specs-core#2646); this handler
//! settles it as follows:
//!
//! * The C2PA stream is one packet, laced across as many pages as it needs. Its first page
//!   is a beginning-of-stream (BOS) page and its last an end-of-stream (EOS) page.
//! * Its pages are inserted, contiguously, directly after the file's leading BOS pages.
//!   RFC 3533 requires every BOS page to come before any other page, and Vorbis requires its
//!   identification header to be alone on the first page, so this is the earliest place the
//!   continuation pages of a large manifest can go.
//! * A file with more than one C2PA stream is treated as having no manifest.
//! * `get_object_locations` still reports the C2PA stream's pages, for callers that bind an
//!   Ogg file with a data hash instead.
//!
//! The pages of the other logical bitstreams are kept byte for byte.

use crate::{
    asset_io::{
        AssetBoxHash, AssetIO, BoxMap, C2paReader, C2paWriter, ObjectLocations, ObjectType,
        ReadSeek, ReadWriteSeek, C2PA_BOXHASH,
    },
    error::{Error, Result},
    utils::io_utils::{stream_len, ReaderUtils},
};

static SUPPORTED_TYPES: [&str; 4] = ["ogg", "oga", "audio/ogg", "audio/vorbis"];

const CAPTURE_PATTERN: &[u8; 4] = b"OggS";
/// The identifier that starts the first packet of the C2PA logical bitstream.
const C2PA_IDENTIFIER: &[u8; 5] = b"\x00c2pa";
/// Serial number for a new C2PA logical bitstream ("c2pa"), unless already in use.
const C2PA_SERIAL: u32 = 0x6332_7061;

const HEADER_LEN: usize = 27;
const MAX_SEGMENTS: usize = 255;

const FLAG_CONTINUED: u8 = 0x01;
const FLAG_BOS: u8 = 0x02;
const FLAG_EOS: u8 = 0x04;

/// Granule position of a page on which no packet ends (RFC 3533, section 6).
const NO_GRANULE: u64 = u64::MAX;

/// Placeholder used to lay out the exclusion before a manifest exists.
const PLACEHOLDER_STORE: &[u8] = b"placeholder manifest";

struct Page {
    start: usize,
    /// Start of the page's packet data, after the header and segment table.
    data_start: usize,
    end: usize,
    flags: u8,
    serial: u32,
    lacing_start: usize,
    segments: usize,
}

impl Page {
    fn is_bos(&self) -> bool {
        self.flags & FLAG_BOS != 0
    }

    fn lacing<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.lacing_start..self.lacing_start + self.segments]
    }
}

fn invalid(msg: &str) -> Error {
    Error::InvalidAsset(format!("Ogg: {msg}"))
}

/// The Ogg CRC-32: polynomial 0x04C11DB7, initial value 0, unreflected, no final XOR.
fn crc32(bytes: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut r = (i as u32) << 24;
            let mut bit = 0;
            while bit < 8 {
                r = if r & 0x8000_0000 != 0 {
                    (r << 1) ^ 0x04c1_1db7
                } else {
                    r << 1
                };
                bit += 1;
            }
            table[i] = r;
            i += 1;
        }
        table
    };
    bytes.iter().fold(0u32, |crc, &b| {
        (crc << 8) ^ TABLE[((crc >> 24) as u8 ^ b) as usize]
    })
}

fn parse_pages(data: &[u8]) -> Result<Vec<Page>> {
    if !data.starts_with(CAPTURE_PATTERN) {
        return Err(Error::UnsupportedType);
    }
    let mut pages = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let header = data
            .get(pos..pos + HEADER_LEN)
            .ok_or_else(|| invalid("truncated page header"))?;
        if &header[..4] != CAPTURE_PATTERN || header[4] != 0 {
            return Err(invalid("bad capture pattern or version"));
        }
        let segments = header[26] as usize;
        let lacing_start = pos + HEADER_LEN;
        let lacing = data
            .get(lacing_start..lacing_start + segments)
            .ok_or_else(|| invalid("truncated segment table"))?;
        let data_start = lacing_start + segments;
        let end = data_start + lacing.iter().map(|&l| l as usize).sum::<usize>();
        if end > data.len() {
            return Err(invalid("truncated page"));
        }
        pages.push(Page {
            start: pos,
            data_start,
            end,
            flags: header[5],
            serial: u32::from_le_bytes([header[14], header[15], header[16], header[17]]),
            lacing_start,
            segments,
        });
        pos = end;
    }
    Ok(pages)
}

/// Serial numbers of the logical bitstreams whose first packet starts with `\x00c2pa`.
fn c2pa_serials(data: &[u8], pages: &[Page]) -> Vec<u32> {
    pages
        .iter()
        .filter(|p| p.is_bos() && data[p.data_start..p.end].starts_with(C2PA_IDENTIFIER))
        .map(|p| p.serial)
        .collect()
}

/// The first packet of the logical bitstream `serial`.
fn first_packet(data: &[u8], pages: &[Page], serial: u32) -> Result<Vec<u8>> {
    let mut packet = Vec::new();
    for page in pages.iter().filter(|p| p.serial == serial) {
        let mut pos = page.data_start;
        for &len in page.lacing(data) {
            packet.extend_from_slice(&data[pos..pos + len as usize]);
            pos += len as usize;
            if len < 255 {
                return Ok(packet);
            }
        }
    }
    Err(invalid("the C2PA packet is not terminated"))
}

/// The byte range of the C2PA stream's pages, which must be contiguous.
fn stream_range(pages: &[Page], serial: u32) -> Result<(usize, usize)> {
    let indices: Vec<usize> = pages
        .iter()
        .enumerate()
        .filter(|(_, p)| p.serial == serial)
        .map(|(i, _)| i)
        .collect();
    let (first, last) = match (indices.first(), indices.last()) {
        (Some(&first), Some(&last)) => (first, last),
        _ => return Err(Error::JumbfNotFound),
    };
    if last - first + 1 != indices.len() {
        return Err(invalid("the C2PA stream's pages are not contiguous"));
    }
    Ok((pages[first].start, pages[last].end))
}

/// Pages for a logical bitstream `serial` holding one packet, `\x00c2pa` + `store_bytes`.
fn build_c2pa_pages(store_bytes: &[u8], serial: u32) -> Vec<u8> {
    let mut packet = C2PA_IDENTIFIER.to_vec();
    packet.extend_from_slice(store_bytes);

    // Lacing: a run of 255s, then a final value below 255 (possibly 0) that ends the packet.
    let mut lacing = vec![255u8; packet.len() / 255];
    lacing.push((packet.len() % 255) as u8);

    let chunks: Vec<&[u8]> = lacing.chunks(MAX_SEGMENTS).collect();
    let mut out = Vec::with_capacity(packet.len() + chunks.len() * (HEADER_LEN + MAX_SEGMENTS));
    let mut offset = 0;
    for (sequence, chunk) in chunks.iter().enumerate() {
        let last = sequence == chunks.len() - 1;
        let mut flags = 0;
        if sequence == 0 {
            flags |= FLAG_BOS;
        } else {
            flags |= FLAG_CONTINUED;
        }
        if last {
            flags |= FLAG_EOS;
        }
        let granule = if last { 0 } else { NO_GRANULE };
        let size: usize = chunk.iter().map(|&l| l as usize).sum();

        let start = out.len();
        out.extend_from_slice(CAPTURE_PATTERN);
        out.push(0); // version
        out.push(flags);
        out.extend_from_slice(&granule.to_le_bytes());
        out.extend_from_slice(&serial.to_le_bytes());
        out.extend_from_slice(&(sequence as u32).to_le_bytes());
        out.extend_from_slice(&[0; 4]); // CRC, filled in below
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
        out.extend_from_slice(&packet[offset..offset + size]);
        offset += size;

        let crc = crc32(&out[start..]);
        out[start + 22..start + 26].copy_from_slice(&crc.to_le_bytes());
    }
    out
}

/// Returns `data` with a C2PA stream for `store_bytes` in place of any existing one, and the
/// byte range of its pages.
fn embed(data: &[u8], store_bytes: &[u8]) -> Result<(Vec<u8>, (usize, usize))> {
    let pages = parse_pages(data)?;
    let existing = c2pa_serials(data, &pages);

    // Drop every page of every C2PA stream, then insert one after the leading BOS pages.
    let mut kept = Vec::with_capacity(data.len());
    let mut insert_at = None;
    let mut in_leading_bos = true;
    for page in &pages {
        if existing.contains(&page.serial) {
            continue;
        }
        if in_leading_bos && !page.is_bos() {
            insert_at = Some(kept.len());
            in_leading_bos = false;
        }
        kept.extend_from_slice(&data[page.start..page.end]);
    }
    let insert_at = insert_at.unwrap_or(kept.len());

    let serial = match existing.first() {
        Some(&serial) => serial,
        None => {
            let mut serial = C2PA_SERIAL;
            while pages.iter().any(|p| p.serial == serial) {
                serial = serial.wrapping_add(1);
            }
            serial
        }
    };
    let c2pa_pages = build_c2pa_pages(store_bytes, serial);

    let mut out = Vec::with_capacity(kept.len() + c2pa_pages.len());
    out.extend_from_slice(&kept[..insert_at]);
    out.extend_from_slice(&c2pa_pages);
    out.extend_from_slice(&kept[insert_at..]);
    Ok((out, (insert_at, c2pa_pages.len())))
}

fn read_all(mut input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
    input_stream.rewind()?;
    let len = stream_len(input_stream)?;
    input_stream.read_to_vec(len)
}

pub struct OggIO {}

impl C2paReader for OggIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let data = read_all(input_stream)?;
        let pages = parse_pages(&data)?;
        // More than one C2PA stream is treated as no manifest.
        let [serial] = c2pa_serials(&data, &pages)[..] else {
            return Err(Error::JumbfNotFound);
        };
        let packet = first_packet(&data, &pages, serial)?;
        let store = packet[C2PA_IDENTIFIER.len()..].to_vec();
        if store.is_empty() {
            return Err(Error::JumbfNotFound);
        }
        Ok(store)
    }

    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl C2paWriter for OggIO {
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
        let pages = parse_pages(&data)?;
        let (full_len, (start, end)) = match c2pa_serials(&data, &pages)[..] {
            [serial] => (data.len(), stream_range(&pages, serial)?),
            [] => {
                // No manifest yet: lay out the exclusion with a placeholder.
                let (out, (start, len)) = embed(&data, PLACEHOLDER_STORE)?;
                (out.len(), (start, start + len))
            }
            _ => return Err(invalid("more than one C2PA logical bitstream")),
        };
        Ok(vec![
            ObjectLocations {
                offset: start as u64,
                length: (end - start) as u64,
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
        let pages = parse_pages(&data)?;
        let serials = c2pa_serials(&data, &pages);
        output_stream.rewind()?;
        for page in pages.iter().filter(|p| !serials.contains(&p.serial)) {
            output_stream.write_all(&data[page.start..page.end])?;
        }
        Ok(())
    }
}

impl AssetBoxHash for OggIO {
    fn get_box_map(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<BoxMap>> {
        let data = read_all(input_stream)?;
        let pages = parse_pages(&data)?;
        let c2pa = c2pa_serials(&data, &pages);
        if c2pa.len() > 1 {
            return Err(invalid("more than one C2PA logical bitstream"));
        }

        // Each logical bitstream, in the order of its first page, with its pages merged into
        // contiguous runs.
        let mut streams: Vec<(u32, Vec<(u64, u64)>)> = Vec::new();
        for page in &pages {
            let run = (page.start as u64, (page.end - page.start) as u64);
            match streams
                .iter_mut()
                .find(|(serial, _)| *serial == page.serial)
            {
                Some((_, runs)) => match runs.last_mut() {
                    Some(last) if last.0 + last.1 == run.0 => last.1 += run.1,
                    _ => runs.push(run),
                },
                None => streams.push((page.serial, vec![run])),
            }
        }

        let mut box_maps: Vec<BoxMap> = streams
            .into_iter()
            .map(|(serial, runs)| {
                let name = if c2pa.contains(&serial) {
                    C2PA_BOXHASH.to_string()
                } else {
                    format!("Stream-{serial}")
                };
                BoxMap::new(vec![name], 0, 0).with_segments(runs)
            })
            .collect();

        // Before signing, the C2PA stream does not exist yet. Report a placeholder where
        // `write_c2pa` will insert it: after the streams that start in the leading BOS pages.
        if c2pa.is_empty() {
            let leading = pages.iter().take_while(|p| p.is_bos()).count();
            let at = pages.get(leading).map_or(data.len(), |p| p.start);
            box_maps.insert(
                leading.min(box_maps.len()),
                BoxMap::new(vec![C2PA_BOXHASH.to_string()], at as u64, 0),
            );
        }

        Ok(box_maps)
    }

    /// The 2.5 specification defines a General Box Hash for Ogg ("Ogg-specific Handling").
    fn requires_box_hash(&self) -> bool {
        true
    }
}

impl AssetIO for OggIO {
    fn new(_asset_type: &str) -> Self {
        OggIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(OggIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(OggIO::new(asset_type)))
    }

    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    const SAMPLE: &[u8] = include_bytes!("../../tests/fixtures/sample1.ogg");

    fn write(source: &[u8], store: &[u8]) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        OggIO {}
            .write_c2pa(&mut Cursor::new(source.to_vec()), &mut output, store)
            .unwrap();
        output.into_inner()
    }

    fn read(data: &[u8]) -> Result<Vec<u8>> {
        OggIO {}.read_c2pa(&mut Cursor::new(data.to_vec()))
    }

    fn c2pa_location(data: &[u8]) -> ObjectLocations {
        OggIO {}
            .get_object_locations(&mut Cursor::new(data.to_vec()))
            .unwrap()
            .into_iter()
            .find(|l| l.htype == ObjectType::C2pa)
            .unwrap()
    }

    /// Every page's CRC matches its contents.
    fn assert_crcs(data: &[u8]) {
        for page in parse_pages(data).unwrap() {
            let mut bytes = data[page.start..page.end].to_vec();
            let stored = u32::from_le_bytes(bytes[22..26].try_into().unwrap());
            bytes[22..26].fill(0);
            assert_eq!(
                crc32(&bytes),
                stored,
                "page at {} has a bad CRC",
                page.start
            );
        }
    }

    #[test]
    fn crc_matches_the_fixture() {
        assert_crcs(SAMPLE);
    }

    #[test]
    fn round_trips_and_keeps_the_vorbis_pages() {
        let out = write(SAMPLE, b"store bytes");
        assert_eq!(read(&out).unwrap(), b"store bytes");
        assert_crcs(&out);

        let loc = c2pa_location(&out);
        let (start, end) = (loc.offset as usize, (loc.offset + loc.length) as usize);
        // The Vorbis stream is unchanged around the C2PA pages.
        assert_eq!([&out[..start], &out[end..]].concat(), SAMPLE);
        // The C2PA pages come straight after the Vorbis identification (BOS) page.
        let first = &parse_pages(SAMPLE).unwrap()[0];
        assert_eq!(start, first.end);
    }

    #[test]
    fn c2pa_stream_is_one_bos_to_eos_packet() {
        let out = write(SAMPLE, b"store bytes");
        let pages = parse_pages(&out).unwrap();
        let serial = c2pa_serials(&out, &pages)[0];
        assert_eq!(serial, C2PA_SERIAL);
        let stream: Vec<&Page> = pages.iter().filter(|p| p.serial == serial).collect();
        assert_eq!(stream.len(), 1);
        assert_eq!(stream[0].flags, FLAG_BOS | FLAG_EOS);
        assert!(out[stream[0].data_start..].starts_with(b"\x00c2pastore bytes"));
        // RFC 3533 grouping: every BOS page precedes every other page.
        let first_non_bos = pages.iter().position(|p| !p.is_bos()).unwrap();
        assert!(pages[first_non_bos..].iter().all(|p| !p.is_bos()));
    }

    #[test]
    fn large_store_spans_contiguous_pages() {
        let store: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let out = write(SAMPLE, &store);
        assert_eq!(read(&out).unwrap(), store);
        assert_crcs(&out);

        let pages = parse_pages(&out).unwrap();
        let stream: Vec<&Page> = pages.iter().filter(|p| p.serial == C2PA_SERIAL).collect();
        assert!(stream.len() >= 4);
        assert_eq!(stream[0].flags, FLAG_BOS);
        assert!(stream[1..stream.len() - 1]
            .iter()
            .all(|p| p.flags == FLAG_CONTINUED));
        assert_eq!(stream.last().unwrap().flags, FLAG_CONTINUED | FLAG_EOS);
        let loc = c2pa_location(&out);
        assert_eq!(loc.offset as usize, stream[0].start);
        assert_eq!(
            (loc.offset + loc.length) as usize,
            stream.last().unwrap().end
        );
    }

    #[test]
    fn store_ending_on_a_lacing_boundary_is_terminated() {
        // 255 * 2 - 5 bytes of store make the packet an exact multiple of 255.
        let store = vec![1u8; 255 * 2 - C2PA_IDENTIFIER.len()];
        let out = write(SAMPLE, &store);
        assert_eq!(read(&out).unwrap(), store);
    }

    #[test]
    fn placeholder_layout_matches_the_written_layout() {
        let before = c2pa_location(SAMPLE);
        let after = c2pa_location(&write(SAMPLE, &vec![9u8; PLACEHOLDER_STORE.len()]));
        assert_eq!((before.offset, before.length), (after.offset, after.length));
    }

    #[test]
    fn replacing_keeps_the_serial_and_position() {
        let first = write(SAMPLE, b"AAAA");
        let second = write(&first, b"BBBB");
        assert_eq!(c2pa_location(&first).offset, c2pa_location(&second).offset);
        let pages = parse_pages(&second).unwrap();
        assert_eq!(c2pa_serials(&second, &pages), vec![C2PA_SERIAL]);
        assert_eq!(read(&second).unwrap(), b"BBBB");
    }

    #[test]
    fn serial_in_use_is_not_reused() {
        let mut sample = SAMPLE.to_vec();
        // Renumber the Vorbis stream to the C2PA default serial, fixing each CRC.
        for page in parse_pages(SAMPLE).unwrap() {
            sample[page.start + 14..page.start + 18].copy_from_slice(&C2PA_SERIAL.to_le_bytes());
            sample[page.start + 22..page.start + 26].fill(0);
            let crc = crc32(&sample[page.start..page.end]);
            sample[page.start + 22..page.start + 26].copy_from_slice(&crc.to_le_bytes());
        }
        let out = write(&sample, b"store");
        let pages = parse_pages(&out).unwrap();
        assert_eq!(c2pa_serials(&out, &pages), vec![C2PA_SERIAL + 1]);
        assert_eq!(read(&out).unwrap(), b"store");
    }

    #[test]
    fn two_c2pa_streams_are_treated_as_no_manifest() {
        let out = write(SAMPLE, b"first");
        let at = parse_pages(SAMPLE).unwrap()[0].end;
        let extra = build_c2pa_pages(b"second", C2PA_SERIAL + 7);
        let doubled = [&out[..at], &extra, &out[at..]].concat();
        assert!(matches!(read(&doubled), Err(Error::JumbfNotFound)));
        assert!(OggIO {}
            .get_object_locations(&mut Cursor::new(doubled))
            .is_err());
    }

    #[test]
    fn remove_restores_the_original() {
        let out = write(SAMPLE, b"store");
        let mut output = Cursor::new(Vec::new());
        OggIO {}
            .remove_c2pa(&mut Cursor::new(out), &mut output)
            .unwrap();
        assert_eq!(output.into_inner(), SAMPLE);
    }

    fn box_names(data: &[u8]) -> Vec<String> {
        OggIO {}
            .get_box_map(&mut Cursor::new(data.to_vec()))
            .unwrap()
            .into_iter()
            .map(|bm| bm.names[0].clone())
            .collect()
    }

    #[test]
    fn box_map_has_a_box_per_logical_bitstream() {
        // Before signing: the Vorbis stream, and a placeholder where the C2PA pages will go.
        assert_eq!(box_names(SAMPLE), vec!["Stream-0", C2PA_BOXHASH]);

        let out = write(SAMPLE, b"store");
        assert_eq!(box_names(&out), vec!["Stream-0", C2PA_BOXHASH]);

        let map = OggIO {}.get_box_map(&mut Cursor::new(out.clone())).unwrap();
        // The Vorbis stream is split by the C2PA pages after its first page: two runs that
        // together are exactly the original file.
        let vorbis: Vec<u8> = map[0]
            .hash_ranges()
            .iter()
            .flat_map(|&(start, len)| out[start as usize..(start + len) as usize].to_vec())
            .collect();
        assert_eq!(map[0].segments.len(), 2);
        assert_eq!(vorbis, SAMPLE);
        let c2pa = c2pa_location(&out);
        assert_eq!(map[1].hash_ranges(), vec![(c2pa.offset, c2pa.length)]);
    }

    #[test]
    fn box_names_use_the_little_endian_serial() {
        let mut sample = SAMPLE.to_vec();
        for page in parse_pages(SAMPLE).unwrap() {
            sample[page.start + 14..page.start + 18].copy_from_slice(&[0x47, 0xb3, 0xc0, 0x5d]);
            sample[page.start + 22..page.start + 26].fill(0);
            let crc = crc32(&sample[page.start..page.end]);
            sample[page.start + 22..page.start + 26].copy_from_slice(&crc.to_le_bytes());
        }
        assert_eq!(box_names(&sample)[0], format!("Stream-{}", 0x5dc0_b347u32));
    }

    #[test]
    fn box_hash_verifies_and_detects_changes() {
        use crate::assertions::BoxHash;

        let handler = OggIO {};
        let mut box_hash = BoxHash { boxes: Vec::new() };
        box_hash
            .generate_box_hash_from_stream(
                &mut Cursor::new(SAMPLE.to_vec()),
                "sha256",
                &handler,
                true,
            )
            .unwrap();
        // One entry per box even when the minimal form is asked for: the Vorbis box is
        // segmented once the C2PA pages are in, so boxes can't be collapsed.
        let names: Vec<&str> = box_hash.boxes.iter().map(|b| b.names[0].as_str()).collect();
        assert_eq!(names, vec!["Stream-0", C2PA_BOXHASH]);

        let signed = write(SAMPLE, b"store");
        box_hash
            .verify_in_memory_hash(&signed, Some("sha256"), &handler)
            .unwrap();

        let mut tampered = signed.clone();
        let last = tampered.len() - 100;
        tampered[last] ^= 0xff;
        assert!(box_hash
            .verify_in_memory_hash(&tampered, Some("sha256"), &handler)
            .is_err());
    }

    #[test]
    fn non_ogg_is_unsupported() {
        assert!(matches!(read(b"RIFF....WAVE"), Err(Error::UnsupportedType)));
    }
}
