---
title: Goose CLI
description: Run Goose CLI through Pentect without changing saved Goose settings.
---

## Start

```sh
pentect goose
```

Choose a model or pass normal Goose CLI arguments:

```sh
pentect goose --model gpt-5 session
```

Pentect sets process-only provider values. The main, fast, and planner model
routes use the same local OpenAI-compatible gateway. Saved Goose settings and
keychain entries are not changed.

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
