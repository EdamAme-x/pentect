---
title: Gemini CLI
description: Run Gemini CLI through Pentect's native Gemini API gateway.
---

## Start

Use Gemini CLI's **Gemini API key** authentication. The CLI reads the key from
`GEMINI_API_KEY`. Then launch it through Pentect:

```sh
pentect gemini
```

Normal Gemini CLI arguments pass through:

```sh
pentect gemini --model gemini-2.5-pro
```

Pentect sets `GOOGLE_GEMINI_BASE_URL` only for the launched process. It speaks
the native Gemini API; it does not convert Gemini requests to OpenAI format.

::: warning Authentication mode
This adapter covers Gemini CLI's `gemini-api-key` mode only. Google sign-in,
Gemini Code Assist, and Vertex AI use different endpoints and are not routed
through this gateway. Do not treat those modes as protected by `pentect gemini`.
:::

## Protected

- `generateContent` and `streamGenerateContent`
- `countTokens` request content
- Text, supported inline data, function responses, and function calls
- Known handles restored only inside returned function-call arguments

Model-list requests pass through because they do not contain prompts.

## Not protected by this command

- Google sign-in and Gemini Code Assist OAuth traffic
- Vertex AI, including express mode
- Remote file content referenced only by `fileData`
- A Gemini process started without `pentect gemini`

Remote `fileData` is blocked by the default unchecked-media policy because
Pentect cannot fetch and inspect it. If that policy is changed, the remote file
is still not protected by Pentect.

Unknown native Gemini request or response parts are blocked by default. See
[Compatibility](/reference/compatibility/) before enabling the unknown-format
compatibility setting.
