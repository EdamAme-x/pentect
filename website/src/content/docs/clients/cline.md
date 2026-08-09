---
title: Cline CLI
description: Run a local Cline CLI session through Pentect.
---

## Start

```sh
pentect cline
```

Choose a model or pass normal task arguments:

```sh
pentect cline --model gpt-5 "Review this project"
```

Pentect starts Cline with a temporary provider registry and data directory.
The registry is removed when Cline exits. Your normal Cline settings are not
changed.

## Protected

- Local Cline CLI prompts and streamed model responses
- Text and supported image input
- MCP and tool results carried by the OpenAI-compatible request
- Completed tool-call arguments restored at the local tool boundary

## Not protected by this command

- The Cline extension in an existing VS Code window
- Cline account and management commands
- Detached `cline --zen` sessions

`--zen` is rejected because the detached process would outlive the local
Pentect gateway. Run it outside Pentect instead.

Use `--upstream URL` for a compatible provider. See
[Custom upstreams](/clients/upstreams/).
