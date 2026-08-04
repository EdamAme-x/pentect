---
title: Quick start
description: Protect a real Codex or Claude session in a few commands.
---

1. Check that Pentect can find your client.

   ```sh
   pentect doctor
   ```

2. Launch the client through Pentect.

   ```sh
   pentect codex
   # or
   pentect claude
   ```

3. Work normally.

   Ask the agent to read a local configuration file or perform a task that
   requires a credential. Protected values appear to the model as handles such
   as `<<DATABASE_URL_4ce8a3b0a6f64e12>>`.

4. Watch local protection events when needed.

   ```sh
   pentect log
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

The output contains reusable handles. Plaintext is not printed back to the
terminal.

::: tip
These functions affect only that shell. Pentect protects each client process
launched through them; it does not create a system-wide proxy.
:::
