---
title: OpenCode
description: Run OpenCode through a temporary Pentect provider.
---

```sh
pentect opencode --model openai/gpt-5
```

Pentect adds an OpenAI-compatible provider to `OPENCODE_CONFIG_CONTENT` for
this process only. It does not edit `opencode.json` or change normal OpenCode
launches. The main model, small model, and provider allowlist are fixed to the
temporary provider for this launch, so background tasks and subagents cannot
select an unprotected provider.

Normal OpenCode arguments pass through. A model flag may appear anywhere:

```sh
pentect opencode "Review this project" --model openai/gpt-5
```

Chat Completions is the default. Select Responses when the upstream supports
it:

```sh
pentect opencode --api responses --model gpt-5
```

For Bifrost or another compatible gateway, keep its complete base path:

```sh
pentect opencode --model anthropic/claude-sonnet \
  --upstream http://127.0.0.1:8080/openai/v1
```

If no model is given, Pentect uses `gpt-5`. `OPENAI_BASE_URL` is used when
`--upstream` is absent. Authentication still comes from the client environment
or `PENTECT_UPSTREAM_AUTHORIZATION`.
