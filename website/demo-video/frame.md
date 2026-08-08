---
background: "#0b0a09"
surface: "#141210"
foreground: "#f4f1ec"
muted: "#928e88"
accent: "#ff5b36"
success: "#91d99b"
display_font: "Segoe UI"
mono_font: "Cascadia Mono"
corner_radius: 16
---

# Pentect launch frame

The video should feel precise, calm, and inevitable. It shows an actual AI workflow rather than an architecture diagram.

## Rules

- Keep the Claude-like client visible so every action has context.
- Treat the secret as one continuous subject while it crosses Pentect.
- Use black, warm white, and Pentect orange only; green is reserved for success.
- No floating explainer cards, neon glow, bounce, or decorative gradients.
- Do not add status labels, timers, transport labels, or other fake interface metadata.
- The client workspace is `~/ec`; Pentect must not appear as the user's project.
- Motion is directional: request moves right, command moves left, local execution stays left.
- Use sharp ease-outs for UI states and a fast linear wipe for secret replacement.
- Hold the provider-visible handle long enough to read.
- Keep each beat sequential: read, transform, think, restore, then execute locally.
- Never overlap a moving request with the local command result.
- Replace the complete credential fragment so punctuation cannot remain detached.
- Truncate fake credential examples with an ellipsis; never fill the UI with a long token.
- Use one shared syntax-highlighted command component in the provider, transit, and client views.
- The outbound object is the exact user prompt, not a proxy-generated summary.
- Use shadcn-like surfaces: thin borders, restrained radius, and subtle inset highlights.
- Do not use a decorative grid behind the product UI.
- Use the 1920px composition grid: 72px outer margins, 960px client, 96px Pentect rail, 720px provider.
- Derive all major positions from shared layout constants; do not introduce one-off panel coordinates.
- Claude Code is a left-aligned terminal transcript: `❯` input, plain response text, `● Bash(...)`, and `⎿` output.
- Use `Upstream` for the external endpoint because Claude Code may use Anthropic, Bedrock, Vertex, or a gateway.
- Never move and transform a value at the same time; stop it on the Pentect boundary before replacement.
- Embed Geist Variable for brand UI and JetBrains Mono Variable for terminal and protocol text.
- Use a restrained 12/16/22px type scale instead of arbitrary text sizes.
- Do not animate request or command text across the canvas; use boundary activity and in-place reveals.
- Keep surfaces neutral black and gray. Orange is an accent, not a panel tint.
