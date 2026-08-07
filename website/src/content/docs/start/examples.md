---
title: Examples
description: Copyable ways to use Pentect in everyday work.
---

Each example uses fake data. Start a client through Pentect before you use a
handle in that client.

## Paste a secret into a prompt

If you paste a credential into a protected client, Pentect checks it before the
request leaves your computer:

```text
Use OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX to test the account.
```

The provider receives a handle instead of the detected value:

```text
Use OPENAI_API_KEY=<<OPENAI_API_KEY_...>> to test the account.
```

The original text can remain visible in the local client UI. This protection
applies to requests sent through a supported Pentect launch.

## Keep an accidental tool result local

An agent may run a command that prints a token, read a sensitive log line, or
receive a secret in clipboard text. Pentect checks supported tool output before
the next provider request and replaces the value with a handle.

The same rule applies to supported MCP results. Text, JSON fields, page
snapshots, and clipboard data can be protected even when the agent did not know
that the tool would return a secret.

## Create an API key with a browser tool

Suppose an MCP browser opens an admin page and creates a new key. The tool may
return it as structured data:

```json
{"apiKey":"sk-ABCDEFGHIJKLMNOPQRSTUVWX"}
```

Before the result is sent back to the provider, Pentect changes the value to a
handle such as `<<APIKEY_...>>`. A later local tool can use the known handle
without the provider receiving the key.

If the browser returns only a screenshot, Pentect uses local OCR and covers
detected sensitive regions. Read
[Prompts and tool results](/protection/prompts-and-tools/) for the full flow and
[Files and images](/protection/files-and-images/) for OCR limits.

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

Let Pentect add the shell function after showing it to you:

```sh
pentect codex --set-default
pentect claude --set-default
```

Now commands such as `codex exec --full-auto` and `claude --model sonnet` use
Pentect without changing their normal arguments.

Undo the change with `pentect codex --unset-default` or `pentect claude
--unset-default`.

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
