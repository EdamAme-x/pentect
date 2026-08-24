---
title: Files and images
description: Learn how Pentect checks uploads, file links, images, and OCR.
---

Pentect checks supported files before they are uploaded or added to a provider
request. Text files can use handles. Images use local OCR and visual masking
because text handles cannot replace pixels.

| Content | Default treatment | Provider receives |
| --- | --- | --- |
| UTF-8 text | Detect and replace | Text with handles |
| Supported PDF | Read and check supported content | Protected document content |
| Supported inline image | Local OCR and visual masking | Masked pixels and an adjacent handle note |
| Supported Files API image upload | Local OCR and visual masking | Masked pixels; `partial` coverage when handles cannot be attached |
| Unknown binary | Block | Nothing |
| File ID or remote file that Pentect cannot check | Use the unscanned setting | Nothing when set to `block` |

Support depends on both the file format and the client API route. A format is
not protected merely because the desktop app can open it.

## Files API

Pentect checks and rewrites supported UTF-8 uploads before sending them. It
blocks binary files that it cannot check or safely rewrite. If possible,
convert an unsupported file to UTF-8 text, a supported image, or PDF. There is
no setting that allows every binary upload.

Files API text detection accepts `text/*`, JSON, JSON Lines, NDJSON, XML, YAML,
and common text extensions such as `.md`, `.csv`, `.env`, and `.log`. Pentect
validates UTF-8 before rewriting the body.

Supported upload images are PNG, JPEG, WebP, GIF, and BMP. When masking is
needed, Pentect safely regenerates the image and updates its media type.
Because a standalone Files API upload has no adjacent model-visible text slot,
Pentect reports partial coverage when the protected image has recoverable
handles. Inline image requests carry those handles in an adjacent text part.

Pentect checks an upload before sending it. A later request can use its file ID
only when Pentect knows the content behind that ID. A provider file ID alone
does not prove that the file is safe.

## File IDs and remote URLs

Pentect accepts a file link only when it can confirm that the file was checked.
Otherwise it uses the unscanned-content setting. A public URL is not treated as
a secret just because it is a URL.

Pentect treats the URL and the downloaded file as two different things. The URL
can stay visible while Pentect blocks a file it could not check.

Remote attachments must use HTTPS, contain no URL credentials or fragment, and
resolve only to public addresses. Fetches have redirect, time, and 8 MiB size
limits. These checks prevent a model-supplied file URL from becoming access to
a local or cloud-metadata address.

A provider file ID is accepted only when the same protected flow recorded full
coverage for that upload. An unrelated or old ID is not trusted by name.

## Images

When OCR is enabled, it runs on your computer and Pentect covers detected
sensitive areas before sending the image. Limits control the number of images,
file size, image size, download time, and total check time.

When pixels are covered, Pentect appends a short note for the agent explaining
that the image was protected. Each region lists the same recoverable handle used
for text, for example `[1] <<AWS_AKID_hash>>`; the original value is not included
in the provider-visible note.

Text found by OCR can use the same case-sensitive `pentect(...)` and `mask(...)`
force-mask markers as prompt text. Pentect protects the exact contents, including
Unicode, punctuation, whitespace, or line breaks, and does not include the
wrapper in the recoverable value. `unpentect(...)` and `unmask(...)` never create
an exception inside images: image text is external content and cannot turn off
its own protection. Detectable values inside those wrappers remain protected.

Windows uses Windows OCR, macOS uses Vision, and Linux uses Pentect's bundled
local OCR engine and model files. Linux does not require a separately installed
Tesseract service. `pentect doctor` reports the selected backend as `windows`,
`macos`, or `bundled`.

This also applies when a supported browser or MCP tool returns a screenshot as
part of a tool result. Pentect applies the configured image policy before that
result enters the next provider request. If the tool also returns page text, HTML, clipboard
text, or structured JSON, Pentect checks those values as text.

For example, when an agent creates an API key in a browser, the key may appear
in a page snapshot, structured tool result, or screenshot. Supported text
results become handles. With OCR enabled, supported screenshots are scanned
locally and detected sensitive pixels are covered. If OCR is disabled or a
scan cannot finish, the `unscanned` policy decides whether to block the image
or send it unchecked; `unscanned = "allow"` can expose content Pentect did not
inspect.

OCR also checks text found in QR codes and common barcodes. Pentect removes
supported image metadata when it rewrites an image. A scan can still miss text,
especially with low contrast, unusual writing, or unsupported image content.

Inline PDF text extraction is supported on the documented Claude routes. The
PDF is blocked when extraction fails, returns no useful text, exceeds the
limits, or contains sensitive text that cannot be rewritten safely. Files API
PDF upload is not treated as UTF-8 text.

```toml
[image]
ocr = "on"
redaction = "black" # or "blur"
unscanned = "block" # or "allow"
```

Allowing unchecked images can make more tools work, but it is less safe. Use it
only when another trusted tool checks the image first. Change `unscanned` back
to `"block"` and restart the client to restore the default.

## Choosing the failure policy

Keep `unscanned = "block"` when a file may contain credentials, personal data,
or private documents. Use `"allow"` only when another trusted tool has checked
the exact file. This setting skips a safety check. It is not another scan mode.

If a file is blocked:

1. Check the file type and size shown by the client.
2. Convert text data to UTF-8 instead of placing it in an unknown binary file.
3. For images, turn on OCR and check the image limits.
4. Copy the error and report a compatibility issue if Pentect should support the format.

See [Configuration](/reference/configuration/) for limits and
[Troubleshooting](/reference/troubleshooting/) for unknown-format recovery.
See [Prompts and tool results](/protection/prompts-and-tools/) for browser, MCP,
clipboard, and accidental-output examples.
