---
title: Goose CLI
description: Use Goose CLI with Pentect.
---

## Start

```sh
pentect goose
```

Choose a model or pass normal Goose CLI arguments:

```sh
pentect goose --model gpt-5 session
```

Pentect protects this Goose CLI session only. Saved Goose settings and keychain
entries are not changed.

## Protected

- Goose CLI prompts and supported tool results
- Chat Completions streaming and completed tool calls
- Main, fast, and planner requests made by the launched process

## Not protected by this command

- Goose Desktop
- A Goose process started outside `pentect goose`
- Providers that bypass the OpenAI-compatible route

Use `--upstream URL` for another compatible gateway. Pentect keeps upstream
credentials out of Goose's saved configuration.
