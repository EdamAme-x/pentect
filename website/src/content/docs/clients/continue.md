---
title: Continue CLI
description: Run Continue CLI chat, edit, and apply requests through Pentect.
---

## Start

```sh
pentect continue
```

`pentect cn` is a shorter form. Add a model or normal Continue CLI arguments:

```sh
pentect continue --model gpt-5
```

Pentect creates a temporary Continue configuration for this process. Your
normal Continue configuration is not changed.

## Protected

- Chat, Edit, and Apply requests made with the temporary Pentect model
- Text prompts, supported tool results, and completed tool calls
- OpenAI-compatible Chat Completions traffic

## Not protected by this command

- Autocomplete, embeddings, and reranking
- Continue IDE extensions started outside this command
- A config selected with `--agent`

`--agent` is blocked because it can replace the temporary protected model.
Run a different Continue agent without Pentect when you need that option.

Use `--upstream URL` for another OpenAI-compatible provider. See
[Custom upstreams](/clients/upstreams/) for credentials and path rules.
