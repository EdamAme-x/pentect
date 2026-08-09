---
title: VS Code
description: Use a Pentect model in VS Code.
---

## Install the provider

Until the extension is published in the Marketplace, install the release asset
from GitHub:

```sh
curl -fL https://github.com/EdamAme-x/pentect/releases/latest/download/pentect-vscode.vsix -o pentect-vscode.vsix
code --install-extension pentect-vscode.vsix
```

Reload VS Code, then select a model whose provider is **Pentect** in Chat.

The extension starts Pentect when the selected model is used. You do not need
to start another command.

## Protected

- Chat and agent requests that explicitly select the Pentect provider
- Text prompts and text tool results
- Tool definitions, streamed text, and completed tool-call arguments

Unknown VS Code message parts are blocked instead of being sent unchecked.

## Not protected by this provider

- GitHub Copilot's own models
- Inline suggestions and ghost text
- Private HTTP traffic from another extension
- Image input

This is a selectable provider, not a system-wide VS Code proxy. Set the model
and optional OpenAI-compatible upstream in the extension settings. Keep the
provider key in `OPENAI_API_KEY` in the environment used to start VS Code.
