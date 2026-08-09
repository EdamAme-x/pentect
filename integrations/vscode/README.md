# Pentect for VS Code

This extension adds **Pentect** as a selectable VS Code language model provider.
Requests use Pentect's local OpenAI-compatible gateway, so secrets are replaced
before the upstream model receives them and are restored only in completed tool
call arguments.

The extension does not read or store provider API keys. It starts the installed
`pentect` executable on demand and keeps the authenticated loopback gateway alive
only for the VS Code session.

## Install and use

1. Install Pentect and make sure `pentect doctor` succeeds.
2. Install the packaged VSIX.
3. Restart VS Code from an environment that contains `OPENAI_API_KEY`.
4. Select the model whose provider is **Pentect** in VS Code's model picker.

For a compatible custom gateway, set `Pentect › VS Code: Upstream`. Keep its
authorization value in `PENTECT_UPSTREAM_AUTHORIZATION`, not in VS Code settings.

## Scope

- Supported: chat and agent requests that explicitly select the Pentect model.
- Not intercepted: GitHub Copilot's own models, inline suggestions, ghost text,
  or HTTP traffic from other extensions.
- Image input is not advertised until the VS Code input-part mapping has complete
  file and image coverage.

Set provider credentials in the environment used to launch VS Code. Do not put
credentials in VS Code settings.

See [pentect.dev](https://pentect.dev/clients/vscode/) for installation and usage.
