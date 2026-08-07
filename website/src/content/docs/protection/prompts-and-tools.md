---
title: Prompts and tool results
description: See how Pentect protects pasted secrets, accidental output, MCP results, and browser screenshots.
---

Secrets do not only come from `.env` files. They can appear in a prompt, a
terminal response, a browser page, structured MCP data, or a screenshot.
Pentect checks these values before the supported client sends its next request
to the model provider.

## A secret pasted into a prompt

You may paste a token while asking the agent to test an API:

```text
Test the account with OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX
```

When the protected client sends that prompt, Pentect replaces the detected
value first:

```text
Test the account with OPENAI_API_KEY=<<OPENAI_API_KEY_...>>
```

The client UI can still show what you typed locally. The provider receives the
protected request. This applies only when the client was started through
Pentect and the request uses a supported format.

## A secret appears by accident

A tool may print more than expected. Common examples include:

- a command that prints its environment;
- a log containing a connection string;
- a file-read result containing a token;
- clipboard text copied from an admin page;
- JSON returned by an MCP server or connector.

Pentect checks supported tool results before they become part of the next model
request. Text and structured values are replaced with handles. The model can
continue using the safe reference without receiving the original value.

This protection happens on the provider boundary. Pentect cannot take back a
value that another program already sent outside the protected flow.

## An MCP browser creates an API key

An agent can use a browser tool to create a credential without asking you to
copy it into chat. A protected flow looks like this:

1. The model asks the local browser or MCP tool to create the key.
2. The website shows the new key on your computer.
3. The tool returns page text, HTML, JSON, clipboard text, or an image.
4. Pentect checks the supported tool result before the client sends it back to
   the provider.
5. The provider sees a handle such as `<<APIKEY_...>>`.
6. A later local tool can use that known handle through the protected tool
   boundary or its `PENTECT_<LABEL>_<ID>` environment binding.

For example, an MCP result like this:

```json
{
  "structuredContent": {
    "apiKey": "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
  }
}
```

is sent to the provider with the value replaced:

```json
{
  "structuredContent": {
    "apiKey": "<<APIKEY_...>>"
  }
}
```

Pentect does not grant the browser permission to create or use a key. Browser
confirmation, site permissions, and the MCP server's own access rules still
apply. If the browser tool sends a secret directly to a website, that network
side effect happens outside Pentect's provider boundary.

## Screenshots and OCR

A screenshot may contain a token even when the tool result has no useful text.
With OCR enabled, Pentect scans supported image payloads locally and covers
detected sensitive regions before the image is sent to the provider.

Pentect also checks text found in supported QR codes and barcodes. When an
image must be rewritten, it removes supported metadata and sends protected
pixels instead of the original image.

If OCR is disabled or an image cannot be checked, the default setting blocks
it. You can choose to allow unchecked media, but then the provider may receive
content Pentect did not inspect:

```toml
[image]
unscanned = "allow"
```

OCR is not perfect. Low contrast, small text, unusual fonts, handwriting,
cropped content, or an unsupported image format can be missed. Keep browser
and tool permissions limited even when OCR is enabled.

See [Files and images](/protection/files-and-images/) for supported formats,
limits, remote URLs, PDF behavior, and image settings.

## What is covered

| Source | What Pentect does before the provider request |
| --- | --- |
| Prompt text | Replaces detected sensitive values with handles |
| Terminal, file, and log output | Masks supported text returned by a local tool |
| MCP text or structured result | Checks supported strings and structured fields |
| Clipboard text returned by a tool | Masks detected values |
| Supported screenshot or inline image | Runs local OCR and covers detected regions |
| Unknown media or result format | Blocks it by default when it cannot be checked safely |

## What is not covered

- A request made by a client that was not started through Pentect
- Data already sent before Pentect saw it
- A direct network side effect performed inside a browser, MCP server, or local
  tool
- Content hidden in an unsupported or unchecked format
- A sensitive value that no detector or OCR engine finds

Pentect reduces exposure to the model provider. It does not replace browser
approval, MCP permissions, restricted credentials, or normal access control.
