---
title: Junie CLI
description: Run Junie CLI with a temporary Pentect model profile.
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

Pentect creates a private model profile with a local gateway URL and an
environment-variable reference for its key. The profile is removed when Junie
exits. The real upstream key is not written to the profile.

## Protected

- Junie CLI requests made by the temporary custom model
- Chat Completions by default, or Responses with `--api responses`
- Supported prompt, tool-result, streaming, and completed tool-call content

## Not protected by this command

- The Junie IDE plugin
- A different model selected outside the temporary Pentect profile
- Provider APIs other than the selected OpenAI-compatible format

Use `--upstream URL` for a compatible custom provider.
