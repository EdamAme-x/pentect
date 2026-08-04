---
title: How it works
description: Follow a sensitive value from local input to a trusted tool call.
---

Pentect sits between a supported AI client and its model provider. It transforms
supported request and response structures without replacing the client UI.

1. **Detect locally**

   Pentect inspects prompts, supported tool results, configuration formats,
   uploads, and images before protected content crosses the provider boundary.

2. **Replace with an opaque handle**

   ```dotenv
   KAGGLE_API_TOKEN=KGAT_example
   KAGGLE_API_TOKEN=<<KAGGLE_API_TOKEN_85268c441f88c284>>
   ```

   Labels may come from structure, such as a dotenv key. The keyed hash gives
   the same protected value a stable reference within the configured scope.

3. **Let the model use the reference**

   The model can reason about the named value and place the handle in a tool
   call without learning its plaintext.

4. **Resolve only at the trusted boundary**

   Pentect resolves known handles immediately before the local client executes
   a completed tool call. Unknown handle-shaped text remains inert.

5. **Mask results on the way back**

   Tool output is inspected before it returns to the provider, preventing a
   locally restored value from simply leaking back in stdout or a file read.

## Request and response lifecycle

| Stage | Input | Output |
| --- | --- | --- |
| Client request | Provider-shaped JSON, streaming metadata, or supported files | Same protocol with protected values replaced |
| Provider response | Text, events, and completed tool calls | Protocol preserved; known handles remain references |
| Local execution | Completed tool arguments | Known handles resolved just before execution |
| Tool result | stdout, stderr, and supported structured output | Sensitive values replaced before the next provider request |

Pentect transforms protocol fields rather than scraping the terminal UI. This
keeps streaming and normal client interaction intact while putting protection
at the network and local execution boundaries.

## Handle identity

A handle combines a useful label with a keyed digest. Structured sources can
provide the label—`DATABASE_URL` in dotenv, for example—while detectors provide
labels for unstructured text. The digest identifies the protected value without
embedding it in the handle.

Known handles can be resolved by the store that created them. Unknown
handle-shaped text is never guessed or matched to a different value. Handle
stability is configurable; see [Configuration](/reference/configuration/).

## Content that needs a different treatment

Text can carry a reusable handle. Images instead require local OCR and pixel
redaction, while unsupported binary content follows the unscanned-content
policy. [Files and images](/protection/files-and-images/) lists the exact
behavior and controls. [Plugins](/plugins/overview/) can add detection or
middleware without changing the client integration.

## Why handles instead of `[REDACTED]`?

Plain redaction removes both the value and its identity. A Pentect handle keeps
enough context for an agent to finish work while preserving the security
boundary.

::: warning
A handle is a reference, not an authorization decision. If a local tool is
allowed to use the credential, it can act with that credential's privileges.
Use scoped, revocable credentials and narrow tool permissions.
:::
