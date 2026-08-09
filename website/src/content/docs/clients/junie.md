---
title: Junie CLI
description: Use Junie CLI with Pentect.
---

## Start

```sh
pentect junie
```

Select a model and API shape when needed:

```sh
pentect junie --model gpt-5
pentect junie --api responses --model gpt-5
```

Pentect protects the selected model for this Junie CLI session. The upstream
key is not saved in Junie settings.

## Protected

- Junie CLI requests made by the selected Pentect model
- Chat Completions by default, or Responses with `--api responses`
- Supported prompt, tool-result, streaming, and completed tool-call content

## Not protected by this command

- The Junie IDE plugin
- A different model selected outside the Pentect session
- Provider APIs other than the selected OpenAI-compatible format

Use `--upstream URL` for a compatible custom provider.
