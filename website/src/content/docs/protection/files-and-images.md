---
title: Files and images
description: How Pentect handles uploads, file references, remote content, and OCR.
---

Pentect inspects supported file content before it is uploaded or included in a
provider request. Textual formats can preserve opaque handles. Images use local
OCR and visual redaction because pixels cannot carry a textual handle in place.

| Content | Default treatment | Provider receives |
| --- | --- | --- |
| UTF-8 text | Detect and replace | Text with handles |
| Supported PDF | Extract and inspect supported content | Protected document content |
| Supported image | Local OCR and visual redaction | Redacted pixels |
| Unknown binary | Block | Nothing |
| Unverified file ID or remote reference | Apply unscanned-content policy | Nothing when set to `block` |

## Files API

Supported UTF-8 uploads are inspected and rewritten before forwarding. Binary
uploads that Pentect cannot inspect or safely rewrite are blocked by default.
Convert an unsupported upload to UTF-8 text, a supported image, or PDF when
possible. There is no blanket binary-upload bypass.

Inspection happens before forwarding the upload. Later requests that refer to a
file ID are accepted only when Pentect can associate the reference with content
it already covered; an arbitrary provider-side ID is not treated as proof that
the file is safe.

## File IDs and remote URLs

Pentect accepts a file reference only when it can establish safe coverage for
the referenced content. Otherwise the configured unscanned-content policy
applies. Public URLs are not classified as secrets merely because they are URLs.

Pentect distinguishes the URL string from the content behind it. A public URL
can remain visible while an unverified download is still blocked from entering
a protected request.

## Images

OCR runs locally. Detected sensitive regions are redacted before the provider
receives the image. Limits bound image count, byte size, pixel dimensions,
download time, and total processing time.

```toml
[image]
ocr = "on"
redaction = "black" # or "blur"
unscanned = "block" # or "allow"
```

Allowing unscanned images trades protection for compatibility. Use it only
when another trusted layer already inspects the content. Set `unscanned` back
to `"block"` and relaunch the client to restore the default.

## Choosing the failure policy

Keep `unscanned = "block"` when provider-bound content may contain credentials,
personal data, or internal documents. Use `"allow"` only for a workflow where
another trusted control has already inspected the exact bytes. The setting is a
compatibility escape hatch, not a second detection mode.

If a file is blocked:

1. Check the content type and size reported by the client.
2. Convert textual data to UTF-8 rather than wrapping it in an unknown binary.
3. For images, confirm OCR is enabled and the image stays within configured limits.
4. Capture the normal error details and report a compatibility issue if the format should be supported.

See [Configuration](/reference/configuration/) for limits and
[Troubleshooting](/reference/troubleshooting/) for unknown-format recovery.
