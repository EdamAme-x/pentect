---
title: Quick start
description: Protect a real Codex or Claude session in a few commands.
---

## Install

New to Pentect? [Choose your OS and install method](/start/install/). The
installation page covers Windows, macOS, Linux, npm, Homebrew, APT, and Nix.

Already installed? Continue below. You do not need to change the permanent
settings of Codex or Claude.

## Start a protected session

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

You can test the request boundary with fake data. Paste this into the protected
client:

```text
Remember OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX for this task.
```

The provider-bound prompt contains an `<<OPENAI_API_KEY_...>>` handle instead
of the fake value. The same protection applies to supported text returned by a
terminal, file tool, browser, or MCP server.

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

## Use Pentect from your normal CLI command

This step is optional. If you want `codex` or `claude` to use Pentect without
typing the `pentect` prefix, run:

```sh
pentect codex --set-default
pentect claude --set-default
```

Pentect detects PowerShell, Bash, Zsh, or Fish. Before changing anything, it
shows the profile path and the function it will add. It also backs up an
existing profile. Restart the terminal after you approve the change.

After that, launch either client as usual:

```sh
codex exec --full-auto
claude --model sonnet
```

Remove only the profile block created by Pentect with:

```sh
pentect codex --unset-default
pentect claude --unset-default
```

## Add a clickable App launcher

This is also optional. Add a separate protected launcher for the desktop App:

```sh
pentect codex app --install-launcher
pentect claude app --install-launcher
```

| System | Launcher location |
| --- | --- |
| Windows | Start menu → Pentect |
| macOS | `~/Applications` |

Pin `Codex via Pentect` or `Claude via Pentect` to the taskbar or Dock. The
launcher starts the same local Pentect gateway as the terminal command, without
leaving a terminal window open. The official App and its shortcut are not
changed.

Quit the official App before using the protected launcher. An App that is
already running cannot inherit the temporary Pentect routing.

Remove the launcher with:

```sh
pentect codex app --remove-launcher
pentect claude app --remove-launcher
```

The remove command checks that Pentect created the launcher. It will not delete
an unrelated shortcut or App with the same name.

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
The default is optional. It affects only supported clients started from that
shell; it does not create a proxy for the whole system.
:::

## Next steps

- Use [Codex](/clients/codex/) or [Claude](/clients/claude/) for client-specific options.
- See [Structured data](/protection/structured-data/) for dotenv, Terraform, Kubernetes, and JSON behavior.
- Read [Handles](/start/handles/) before copying handles between sessions or scripts.
- Review [Files and images](/protection/files-and-images/) before sending uploads.
- See [Prompts and tool results](/protection/prompts-and-tools/) for pasted
  secrets, accidental output, MCP browsers, and screenshots.
- Run `pentect doctor` again after changing a client installation or provider.
- Copy a complete task from [Examples](/start/examples/).
