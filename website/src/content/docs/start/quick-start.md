---
title: Quick start
description: Protect a real Codex or Claude session in a few commands.
---

Install Pentect first, then use one protected launch. You do not need to change
the permanent settings of Codex or Claude.

1. Check Pentect and the client.

   ```sh
   pentect doctor
   ```

2. Launch the client through Pentect.

   ```sh
   pentect codex
   # or
   pentect claude
   ```

3. Work normally in the client that opens.

   Ask the agent to read a local config file or do a task that needs a
   credential. The model sees a handle such as
   `<<DATABASE_URL_4ce8a3b0a6f64e12>>` instead of the real value.

   When the agent needs the value in a shell command, it can use the matching
   `PENTECT_DATABASE_URL_4ce8a3b0a6f64e12` environment binding. Pentect adds
   the binding to the protected tool process; it is not a permanent user
   environment variable.

4. Watch local protection events when you need to verify a flow.

   ```sh
   pentect log
   ```

## What success looks like

If a file contains `DATABASE_URL=postgres://...`, the provider sees a handle
instead of the credential:

```dotenv
DATABASE_URL=<<DATABASE_URL_4ce8a3b0a6f64e12>>
```

The agent can copy the handle into a local tool call. Pentect restores it just
before the tool runs. Pentect then masks sensitive command output before it
returns to the provider. `pentect log` records the event and label, not the real
value.

If `echo $env:PENTECT_DATABASE_URL_...` or `echo
$PENTECT_DATABASE_URL_...` appears masked in tool output, that is expected. The
command received the value, and Pentect protected the output on its way back.

The client should still stream responses, run tools, and accept its normal
flags. If a request format cannot be checked, Pentect returns an error instead
of sending it by default.

Normal client arguments pass through unchanged:

```sh
pentect codex exec --full-auto
pentect claude --model sonnet
```

## Launch through Pentect by default

Add these functions to your shell profile, then restart the terminal. Existing
Codex and Claude arguments continue to work normally.

::: code-group

```powershell [PowerShell · $PROFILE]
function codex { & pentect codex @args }
function claude { & pentect claude @args }
```

```sh [Bash · ~/.bashrc or Zsh · ~/.zshrc]
codex() { command pentect codex "$@"; }
claude() { command pentect claude "$@"; }
```

```fish [Fish · ~/.config/fish/config.fish]
function codex
    command pentect codex $argv
end

function claude
    command pentect claude $argv
end
```

:::

After that, launch either client as usual:

```sh
codex exec --full-auto
claude --model sonnet
```

## Try masking without an agent

```sh
cat .env | pentect mask
cat terraform.tfvars | pentect mask
```

PowerShell:

```powershell
Get-Content .env -Raw | pentect mask
```

The output contains reusable handles. Pentect does not print the real values.

::: tip
These functions affect only that shell. Pentect protects clients started by the
functions. It does not create a proxy for the whole system.
:::

## Next steps

- Use [Codex](/clients/codex/) or [Claude](/clients/claude/) for client-specific options.
- See [Structured data](/protection/structured-data/) for dotenv, Terraform, Kubernetes, and JSON behavior.
- Read [Handles](/start/handles/) before copying handles between sessions or scripts.
- Review [Files and images](/protection/files-and-images/) before sending uploads.
- Run `pentect doctor` again after changing a client installation or provider.
- Copy a complete task from [Examples](/start/examples/).
