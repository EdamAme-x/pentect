---
title: How it works
description: See how Pentect protects a value and restores it for a local tool.
---

Pentect runs between a supported AI client and its model provider. It protects
requests and responses without changing the client UI.

1. **Detect locally**

   Pentect checks text typed into a prompt, tool and MCP results, config files,
   uploads, and images before they are sent to the provider.

2. **Replace the value with a handle**

   ```dotenv
   KAGGLE_API_TOKEN=KGAT_example
   KAGGLE_API_TOKEN=<<KAGGLE_API_TOKEN_85268c441f88c284>>
   ```

   Pentect can use a field name, such as a dotenv key, as the handle label.
   Pentect uses a private key to create the handle ID. Your settings control
   how long this ID stays the same.

3. **Let the model use the reference**

   The model can understand the label and put the handle in a tool call. It
   does not need the real value. Protected launches also provide a local
   environment binding such as
   `$env:PENTECT_KAGGLE_API_TOKEN_85268c441f88c284` in PowerShell or
   `$PENTECT_KAGGLE_API_TOKEN_85268c441f88c284` in a POSIX shell.

4. **Restore only before a local tool runs**

   Pentect restores known handles just before the local client runs a tool
   call. Text that only looks like a handle is not restored.

5. **Mask results on the way back**

   Pentect checks tool output before it returns to the provider. This stops a
   restored value from leaking through command output or a file read.

## Request and response lifecycle

| Stage | Input | Output |
| --- | --- | --- |
| Client request | API data, stream data, or supported files | The same format, with sensitive values replaced |
| Provider response | Text, events, and completed tool calls | The same format, with handles kept as references |
| Local execution | Completed tool arguments | Known handles restored just before the tool runs |
| Tool result | stdout, stderr, and supported data | Sensitive values replaced before the next request |

A tool result can come from a shell, file reader, browser, connector, or MCP
server. Supported text and structured fields are checked as they enter the
next provider request. Supported screenshots use the image path instead.

Pentect works with API fields instead of reading the terminal screen. Streaming
and normal client controls continue to work.

## Handle identity

A handle has a useful label and a keyed hash. A config key can provide the
label, such as `DATABASE_URL` in a dotenv file. A detector provides the label
for plain text. The hash identifies the value without putting it in the handle.

Only the local store that knows a handle can restore it. Pentect never guesses
an unknown handle or connects it to another value. You can choose how long a
handle ID stays stable in [Configuration](/reference/configuration/). A stable
ID does not keep recovery data alive after the protected session ends. See
[Handles](/start/handles/) for the full lifecycle.

## Content that needs a different treatment

Text can contain a reusable handle. Images need local OCR and visual masking.
Unknown binary files follow the unscanned-content setting. See
[Files and images](/protection/files-and-images/) for details. Plugins can add
new checks without changing the client setup.

See [Prompts and tool results](/protection/prompts-and-tools/) for examples of
manual input, unexpected output, browser-created keys, and screenshots.

## Why handles instead of `[REDACTED]`?

Plain masking removes both the value and its name. A Pentect handle keeps
enough context for the agent to finish the task.

The handle is not a permission token. It works only when the local Pentect
session knows its value and the local tool already has permission to perform
the action.

::: warning
A handle is only a reference. It does not control permission. A local tool that
uses a credential gets that credential's access. Use limited credentials that
you can revoke, and give tools only the permissions they need.
:::
