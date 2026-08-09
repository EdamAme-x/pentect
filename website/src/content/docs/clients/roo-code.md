---
title: Roo Code
description: Open legacy Roo Code in an isolated VS Code profile through Pentect.
---

::: warning Archived upstream
The [Roo Code repository](https://github.com/RooCodeInc/Roo-Code) is archived.
Pentect keeps this adapter for existing installations, but future Roo changes
will not be treated as a supported moving target.
:::

## Start

Install the `RooVeterinaryInc.roo-cline` extension, close the VS Code window
you want to replace, then run:

```sh
pentect roo
```

Pentect opens a new VS Code window with a temporary user-data directory. It
imports one temporary OpenAI-compatible profile for Roo Code and removes the
profile when the window closes. Your normal VS Code and Roo settings are not
edited.

## Protected

- Roo Code's built-in Code, Architect, Ask, Debug, and Orchestrator modes
- Prompts, supported tool results, images, and streamed tool calls sent through
  the temporary profile
- Values restored only in completed local tool-call arguments

## Limits

This adapter is for the archived Roo Code extension. It does not protect other
VS Code extensions, Copilot, inline completion, or a Roo window opened in your
normal VS Code profile. Flags that replace the temporary profile or disable
extensions are rejected.

Add `--model MODEL` or `--upstream URL` when you need another compatible model
or gateway. Other normal VS Code arguments pass through.
