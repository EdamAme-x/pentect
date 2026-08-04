---
title: Files and images
description: How Pentect handles uploads, file references, remote content, and OCR.
---

Pentect inspects supported file content before it is uploaded or included in a
provider request. Textual formats can preserve opaque handles. Images use local
OCR and visual redaction because pixels cannot carry a textual handle in place.

## Files API

Supported UTF-8 uploads are inspected and rewritten before forwarding. Binary
uploads that Pentect cannot inspect or safely rewrite are blocked by default.

## File IDs and remote URLs

Pentect accepts a file reference only when it can establish safe coverage for
the referenced content. Otherwise the configured unscanned-content policy
applies. Public URLs are not classified as secrets merely because they are URLs.

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
when another trusted layer already inspects the content.
