---
title: OpenCode
description: Use OpenCode with Pentect.
---

```sh
pentect opencode --model openai/gpt-5
```

Pentect protects this OpenCode launch only. It does not edit `opencode.json` or
change normal OpenCode launches. Background tasks and subagents use the same
protected provider during the session.

Normal OpenCode arguments pass through. A model flag may appear anywhere:

```sh
pentect opencode "Review this project" --model openai/gpt-5
```

Chat Completions is the default. Select Responses when the upstream supports
it:

```sh
pentect opencode --api responses --model gpt-5
```

## Custom gateways

For Bifrost or another compatible gateway, keep its complete base path:

```sh
pentect opencode --model anthropic/claude-sonnet \
  --upstream http://127.0.0.1:8080/openai/v1
```

If no model is given, Pentect uses `gpt-5`. Custom endpoint variables and
gateway credentials are advanced options; see
[Custom upstreams](/clients/upstreams/).
