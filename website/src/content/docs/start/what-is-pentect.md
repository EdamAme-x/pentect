---
title: What is Pentect?
description: Protect sensitive data before an AI request leaves your computer.
---

Pentect runs locally between an AI coding tool and its model provider. It
replaces secrets and sensitive data with handles before a request leaves your
computer. A handle is a safe reference such as `<<DATABASE_URL_...>>`.

Use Pentect when an agent needs a credential or sensitive file. The agent can
use the handle without receiving the real value.

## Why normal masking is not enough

Normal masking hides both the value and its name:

```dotenv
DATABASE_URL=[REDACTED]
```

The model cannot use this value in a command. Pentect keeps a named reference:

```dotenv
DATABASE_URL=<<DATABASE_URL_4ce8a3b0a6f64e12>>
```

The model can copy this handle into a tool call. Pentect restores the real value
just before the local tool runs. The model provider does not need to see it.

## Scope

Pentect protects supported AI requests. It is not a password manager or secret
vault. Keep using normal permissions, sandboxes, and access controls.

Pentect does not give an agent new access. It only changes what the model
provider can see. Local tools still use the permissions of the current user.

## One request, end to end

| Step | What Pentect does |
| --- | --- |
| Local input | Finds supported sensitive values and creates handles |
| Request to the provider | Sends handles instead of known real values |
| Model response | Keeps handles in text by default and in tool arguments |
| Before a local tool runs | Restores handles that the current session knows |
| Tool result | Checks and masks output before the next request |

The client UI stays the same. Pentect starts the client with a local gateway for
that process only.

Assistant prose remains masked by default. Users who explicitly prefer local
readability can enable [`output.restore`](/reference/configuration/#assistant-output-restoration).
That opt-in restores only handles known to the active session and can expose the
value to terminal scrollback or client logs.

## Supported surfaces

Pentect supports Codex, Claude, OpenCode, and Pi, plus supported Codex App and
Claude Desktop routes. It also offers local masking commands, custom gateways,
and safe plugins.

Antigravity, Aider, Continue, Cline, Roo Code, Zed, Goose, Junie, and Gemini
CLI are documented as [not implemented](/reference/compatibility/#not-implemented).
Their proposed commands are not available and must not be treated as protected.

See [Compatibility](/reference/compatibility/) for the release-tested matrix.

## When it is useful

Pentect fits work where an AI agent must read configuration, inspect logs, or
call a local tool without sending every credential and private field to the
model provider. Common examples are:

- pasting a credential into a prompt by mistake;
- masking a secret that appears in terminal output, logs, or clipboard text;
- letting an MCP browser create a new API key without returning the real value
  to the model provider;
- covering sensitive text in a browser screenshot with local OCR;
- coding with `.env`, Terraform, Kubernetes, cloud, npm, or PyPI settings;
- letting an agent call an API with a credential already on the computer;
- checking documents and screenshots before they enter a supported request;
- adding a company-specific detector through a reviewed plugin.

See [Prompts and tool results](/protection/prompts-and-tools/) for the complete
flow from local input to provider request.

It is less useful for a client that never exposes a supported local API route,
or for a workflow that already sends the original value outside the protected
client. Pentect cannot take back data that another process has already sent.

## What changes on the computer

Pentect starts the selected client with a temporary local API endpoint. It does
not change the global provider configuration for every launch. The provider
still receives the request and returns the model response; Pentect checks and
rewrites supported content on the way through.

For local commands, `pentect exec` restores known handles only for that command
and masks its output before printing it. See [Handles](/start/handles/) for the
mapping and lifetime rules.
