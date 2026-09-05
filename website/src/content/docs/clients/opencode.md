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

Without `--model`, OpenCode's native picker exposes every provider Pentect can
protect: OpenCode Zen, OpenAI, OpenRouter, Anthropic, and Google. `/connect`
uses those native provider IDs, and each provider has its own local privacy
gateway, so selecting or switching providers in the UI cannot bypass Pentect.

Provider setup and credentials stay under OpenCode's native provider ID. If
`opencode auth list` shows a credential named `pentect` from an older Pentect
release, reconnect the intended native provider once. Pentect does not guess a
destination and copy an ambiguous stored credential automatically.

Run OpenCode's native authentication flow through Pentect before the first
protected conversation when the provider requires an account:

```sh
pentect opencode auth login
```

Authentication commands retain OpenCode's complete provider list and do not
install Pentect's temporary conversation routing. They exchange credentials,
not conversation content. Providers not listed as supported below can be
authenticated there, but protected conversations require a supported provider.

Normal local OpenCode arguments pass through. Attaching to another OpenCode
server bypasses this process's gateway and is rejected. `serve` and `web` stay
loopback-only; explicit non-loopback or mDNS exposure is rejected and inherited
server configuration is narrowed to loopback for that launch. A model flag may
appear anywhere before the explicit `--` separator:

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

An explicit `--model` enables only its matching provider for that protected
launch. Without `--model`, the UI can switch among all supported providers;
each remains bound to its matching local gateway.

Chat Completions is the default. Select Responses when the upstream supports
it:

```sh
pentect opencode --api responses --model gpt-5
```

## Session sharing and export

Protected launches disable OpenCode's external session sharing. The
`opencode export` command is forwarded with OpenCode's own `--sanitize` option.

OpenCode's interactive `/export` command still creates a local transcript that
can contain restored values. Pentect cannot sanitize that client-owned local
file, so review it as sensitive data and do not publish it without inspecting
it first.

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
