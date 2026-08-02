# Desktop apps

Pentect launches an installed desktop app only when you ask it to. Normal app
launches are unchanged.

```text
pentect codex app
pentect claude app
```

Quit the target app completely before launching it through Pentect. Background
processes must also exit so every child process inherits the local gateway.

Check what Pentect would use without launching anything:

```text
pentect codex app --check
pentect claude app --check
```

## Coverage

| Command | Protected surface | Not covered by this command |
| --- | --- | --- |
| `pentect codex app` | Codex mode in the ChatGPT desktop app, over the OpenAI Responses API | ChatGPT Chat and Work |
| `pentect claude app` | Claude Chat completion, supported attachment uploads, outbound JSON safety scanning, and Claude Code model traffic started by the app | Remote Cowork execution, Voice, experimental binary model transports, and unrecognized future opaque routes |

The local app UI is not rewritten. Text you type remains visible locally;
Pentect replaces detected values at the outbound model boundary. Model tool-call
arguments are resolved only at the trusted local tool boundary.

Malformed or recognized-but-unsupported model formats are rejected by default.
Other outbound Claude JSON is scanned generically so telemetry and newly added
JSON routes do not become an easy plaintext bypass. The global compatibility
escape hatch is documented in [configuration](configuration.md).

## Codex mode

`pentect codex app` starts the unmodified app and inserts a loopback-only
Responses API gateway. It temporarily routes the selected Codex provider
through that gateway and restores the exact previous Codex configuration when
the app exits. An interrupted override is recovered on the next launch.

The current ChatGPT desktop app and the earlier standalone Codex app are both
auto-detected on Windows and macOS. Use `--app PATH` for another installation:

```text
pentect codex app --app "C:\path\to\ChatGPT.exe"
```

Do not run a separate Codex CLI process while this App session is open: Codex
surfaces share `~/.codex/config.toml`, so that CLI may also see the temporary
provider route.

For a Responses-compatible custom provider or local gateway:

```text
pentect codex app --upstream http://127.0.0.1:8080/openai/v1
```

## Claude Desktop

`pentect claude app` starts the unmodified app with an explicit local HTTPS
proxy. Pentect creates an ephemeral certificate authority in memory and passes
only its public-key fingerprint to Chromium for this process. It does not add a
certificate to the operating-system trust store.

Claude Chat request bodies on the current `completion`, numbered completion,
and retry routes are masked before they leave the device. Completed tool-call
inputs are restored at the local app boundary; ordinary assistant text keeps
handles opaque. Claude Code sessions started by the app inherit the local
Anthropic Messages gateway. `--upstream` changes the Anthropic endpoint used by
Claude Code; it does not redirect Claude's proprietary Chat service.

```text
pentect claude app --upstream http://127.0.0.1:8080/anthropic
```

Current direct, project, Cowork-attachment, and filestore multipart upload
routes pass through Pentect's file protection before upload. Prepared direct
uploads are correlated with the later filestore write, so a file reference is
trusted only after that write was protected successfully. Supported text is
rewritten; media and partial inspection follow the configured image/document
policy. Unknown upload routes are not claimed as protected.

Claude's optional binary mobile transport and Voice WebSocket cannot currently
be rewritten and are rejected when Pentect recognizes them. Remote Cowork work
may execute beyond this local process boundary and is not covered.

## Plugins

App sessions can enable the same sandboxed plugins as the CLI. Claude Chat runs
request middleware before masking and completed-tool-call middleware before
local restoration:

```text
pentect codex app --plugins company-policy
pentect claude app --plugins company-policy
```

## Troubleshooting

- Run the matching `--check` command first.
- If it reports `Running: yes`, quit the app from its menu or system tray and
  retry. Pentect will not attach to an already-running process.
- If auto-detection fails, pass the actual executable with `--app PATH`.
- Run `pentect doctor` for configuration and installation checks.
- Provider errors are shown by the app; Pentect writes only gateway metadata
  and safe error summaries to stderr, never request bodies.

Linux desktop app launchers are not release-gated. Use `--app PATH` only for an
experimental installation and verify the exact flow before relying on it.

The Windows startup smoke test used while developing this boundary verified
ChatGPT desktop `26.721.4979.0` detection and Claude Desktop `1.24012.9.0`
startup/API loading. Signed GUI versions still change independently of Pentect,
so protocol tests remain the release gate.
