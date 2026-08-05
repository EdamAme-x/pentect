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
| Supported image | Local OCR and visual masking | Masked pixels |
| Unknown binary | Block | Nothing |
| File ID or remote file that Pentect cannot check | Use the unscanned setting | Nothing when set to `block` |

## Files API

Pentect checks and rewrites supported UTF-8 uploads before sending them. It
blocks binary files that it cannot check or safely rewrite. If possible,
convert an unsupported file to UTF-8 text, a supported image, or PDF. There is
no setting that allows every binary upload.

Pentect checks an upload before sending it. A later request can use its file ID
only when Pentect knows the content behind that ID. A provider file ID alone
does not prove that the file is safe.

## File IDs and remote URLs

Pentect accepts a file link only when it can confirm that the file was checked.
Otherwise it uses the unscanned-content setting. A public URL is not treated as
a secret just because it is a URL.

Pentect treats the URL and the downloaded file as two different things. The URL
can stay visible while Pentect blocks a file it could not check.

## Images

OCR runs on your computer. Pentect covers sensitive areas before it sends the
image. Limits control the number of images, file size, image size, download
time, and total check time.

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
