# Supported file formats

The following table summarizes the supported media (asset) file formats. This information is based on what the Rust library supports; other libraries in the SDK support the same formats unless noted otherwise.

> [!NOTE]
> When reading an asset, the SDK first looks at the file name extension to determine the asset type.  If the file has no extension, then the SDK uses the MIME type specified in the API call (if any).
> When the internal header/MIME disagrees with the extension, the SDK uses the extension, not the internal MIME/metadata.
> If there is no file extension nor MIME type, then the SDK "sniffs the bytes" of the asset using [`infer`](https://docs.rs/infer/latest/infer/) to determine the asset type.

`txt` requires the non-default `unstable_plain_text` feature.

| Extensions      | MIME type                                                                      |
| --------------- | ------------------------------------------------------------------------------- |
| `avi`           | `video/msvideo`, `video/x-msvideo`, `video/avi`, `application/x-troff-msvideo`  |
| `avif`          | `image/avif`                                                                    |
| `c2pa`          | `application/x-c2pa-manifest-store`                                             |
| `dng`           | `image/x-adobe-dng`                                                             |
| `flac`          | `audio/flac`                                                                    |
| `gif`           | `image/gif`                                                                     |
| `heic`          | `image/heic`                                                                    |
| `heif`          | `image/heif`                                                                    |
| `jpg`, `jpeg`   | `image/jpeg`                                                                    |
| `jxl`           | `image/jxl`                                                                     |
| `m4a`           | `audio/mp4`                                                                     |
| `mp3`           | `audio/mpeg`                                                                    |
| `mp4`           | `video/mp4`, `application/mp4` <br/>Fragmented MP4 (DASH) supported only for file-based operations from the Rust library. |
| `mov`           | `video/quicktime`                                                               |
| `onnx`          | (none registered) <br/>The manifest is stored Base64-encoded in a `c2pa:manifest` entry of the model's `metadata_props`. Models with external tensor data can't be signed, since the data hash covers only the `.onnx` file. |
| `parquet`       | `application/vnd.apache.parquet` <br/>The manifest is stored Base64-encoded as `c2pa:manifest` in the footer's `key_value_metadata`. Encrypted files are not supported. |
| `pdf`           | `application/pdf`                                                               |
| `png`           | `image/png`                                                                     |
| `svg`           | `image/svg+xml`                                                                 |
| `tif`, `tiff`   | `image/tiff`                                                                    |
| `txt`           | `text/plain`                                                                    |
| `wav`           | `audio/wav`                                                                     |
| `webp`          | `image/webp`                                                                    |

## Experimental feature: BlockFact

The Rust library supports BlockFact media files (format version 2) when the `unstable_blockfact` feature is enabled.

| Extensions | MIME type                   |
| ---------- | --------------------------- |
| `facti`    | `image/vnd.blockfact.facti` |
| `facta`    | `audio/vnd.blockfact.facta` |
| `factv`    | `video/vnd.blockfact.factv` |

## Experimental feature: WARC

The Rust library supports WARC files when the `unstable_warc` feature is enabled. A gzip-compressed WARC (`.warc.gz`) is read and written with the format `warc`. Decompressed data is limited to 1 GiB in total across all gzip members. WARC-zstd files are not supported.

| Extensions | MIME type          |
| ---------- | ------------------ |
| `warc`     | `application/warc` |

## Experimental feature: TTML

The Rust library supports standalone TTML documents when the `unstable_ttml` feature is enabled.

| Extensions     | MIME type              |
| -------------- | ---------------------- |
| `ttml`, `dfxp` | `application/ttml+xml` |

## Experimental feature: Text formats

The Rust library supports the following text formats when the `unstable_structured_text` feature is enabled.

| Extensions       | MIME type               |
| ---------------- | ----------------------- |
| `atom`           | `application/atom+xml`  |
| `css`            | `text/css`              |
| `ini`            | (detected by extension) |
| `js`, `mjs`      | `text/javascript`       |
| `md`, `markdown` | `text/markdown`         |
| `py`             | `text/x-python`         |
| `rss`            | `application/rss+xml`   |
| `sql`            | `application/sql`       |
| `tex`            | `application/x-tex`     |
| `toml`           | `application/toml`      |
| `vtt`            | `text/vtt`              |
| `xhtml`          | `application/xhtml+xml` |
| `xml`            | `application/xml`, `text/xml` |
| `yaml`, `yml`    | `application/yaml`      |

These formats hold either an embedded manifest or a remote manifest URL, but not both. To sign with a URL, set both `Builder::set_remote_url` and `Builder::set_no_embed(true)`. If the file already has a manifest block, signing replaces its reference and keeps its form. A new block in Markdown front matter is a `#` comment line, so the YAML or TOML stays parseable. The hard binding excludes only the bytes from the `BEGIN` delimiter through the `END` delimiter, so this behavior differs from C2PA 2.5 and follows the change proposed in c2pa-org/specs-core#2664.

## Experimental feature: HTML

The Rust library supports HTML when the `unstable_html` feature is enabled.

| Extensions      | MIME type   |
| --------------- | ----------- |
| `html`, `htm`   | `text/html` |

## Experimental feature: MIDI

The Rust library supports Standard MIDI Files when the `unstable_midi` feature is enabled.

| Extensions      | MIME type                                   |
| --------------- | ------------------------------------------- |
| `mid`, `midi`   | `audio/mid`, `audio/midi`, `audio/x-midi`   |
