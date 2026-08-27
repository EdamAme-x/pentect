---
title: OpenCode
description: Use OpenCode with Pentect.
---

```sh
pentect opencode
```

Pentect protects this OpenCode launch only. It does not edit `opencode.json` or
change normal OpenCode launches. Background tasks and subagents use the same
protected provider during the session.

Without `--model`, OpenCode's native Zen provider and model picker remain
available. Pentect keeps the original provider name and model catalog, but
routes its requests through the local privacy gateway.

Provider setup and credentials stay under OpenCode's native provider ID. If
`opencode auth list` shows a credential named `pentect` from an older Pentect
release, reconnect the intended native provider once. Pentect does not guess a
destination and copy an ambiguous stored credential automatically.

Normal OpenCode arguments pass through. A model flag may appear anywhere before
the explicit `--` separator:

```sh
pentect opencode "Review this project" --model openai/gpt-5
```

After `--`, `--model` and `-m` are forwarded unchanged to OpenCode and do not
select Pentect's provider route.

Pentect currently routes native `opencode`, `openai`, `openrouter`, `anthropic`,
and `google` providers. Select one with OpenCode's `provider/model` form:

```sh
pentect opencode run --model openrouter/anthropic/claude-sonnet "Review this project"
```

Only the selected provider is enabled for that protected launch. Start a new
Pentect launch to switch providers; this prevents background agents from
bypassing the matching protocol gateway.

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

With a custom upstream, Pentect treats the model as an OpenAI-compatible
gateway model ID. Custom endpoint variables and gateway credentials are
advanced options; see
[Custom upstreams](/clients/upstreams/).
