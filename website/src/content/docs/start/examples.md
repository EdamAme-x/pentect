---
title: Examples
description: Copyable ways to use Pentect in everyday work.
---

Each example uses fake data. Start a client through Pentect before you use a
handle in that client.

## Read a config file safely

Ask a protected Codex or Claude session to read `.env`. The provider receives
the key names and handles:

```dotenv
DATABASE_URL=<<DATABASE_URL_4ce8a3b0a6f64e12>>
PAYMENTS_TOKEN=<<PAYMENTS_TOKEN_9ef3a9b7b1cf0210>>
```

You can check the same result without an agent:

::: code-group

```sh [macOS / Linux]
cat .env | pentect mask
```

```powershell [Windows]
Get-Content .env -Raw | pentect mask
```

:::

## Let a local command use a handle

`pentect exec` restores handles before the command runs, then masks its output:

```sh
pentect exec 'curl -H "Authorization: Bearer <<API_TOKEN_...>>" https://api.example.test/me'
```

Prefer this to `pentect resolve` when a command can accept the handle directly.
`resolve` writes the real value to a file or standard output.

## Keep your normal client command

Add a small function to your shell profile. Client arguments still pass
through:

::: code-group

```powershell [PowerShell]
function codex { & pentect codex @args }
function claude { & pentect claude @args }
```

```sh [Bash / Zsh]
codex() { command pentect codex "$@"; }
claude() { command pentect claude "$@"; }
```

```fish [Fish]
function codex
    command pentect codex $argv
end
function claude
    command pentect claude $argv
end
```

:::

Now commands such as `codex exec --full-auto` and `claude --model sonnet` use
Pentect without changing their normal arguments.

## Use a local model or gateway

Point one launch at a gateway that supports the client API:

```sh
pentect codex --upstream http://127.0.0.1:8080/openai/v1
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

Codex needs OpenAI Responses. Claude needs Anthropic Messages. A Chat
Completions endpoint alone is not enough. See [Custom upstreams](/clients/upstreams/).

## Apply a project policy

Create `.pentect/config.toml` in the project:

```toml
[handles]
scope = "project"

[agent]
required = true
```

This gives the project its own handle identity and requires supported agents to
start through Pentect. A project cannot turn off the user's unknown-format
protection.

## Add one custom detector

Create `plugins/company/plugin.toml`:

```toml
schema = "pentect.plugin.v1"
name = "company-ids"
description = "Protect internal case IDs."

[[detector]]
label = "CASE_ID"
pattern = '''\bCASE-[0-9]{8}\b'''
category = "identifier"
confidence = "high"
```

Try it for one command:

```sh
echo "CASE-12345678" | pentect mask --plugins ./plugins/company
```

Continue with [Build a plugin](/plugins/build/) when you need Wasm, settings,
network access, or request policy.
