# Using Pentect

Pentect protects sensitive values before requests leave this device. Launch a
supported agent through Pentect, for example `pentect codex` or
`pentect claude`, and otherwise use the agent normally.

Values such as `<<API_KEY_ab12...>>` are opaque handles:

- Copy a handle exactly. Do not edit, expand, guess, or explain it.
- Use it only in a local tool call that needs the represented value.
- Keep an ordinary handle as one complete quoted data argument or string. For
  values Pentect cannot conservatively restore in code or patch text, append
  `|base64` before the closing `>>`, keep that view as one quoted data value,
  and decode it locally through argv, stdin, or another data API. Do not use a
  handle to generate syntax, patch structure, or an `eval` input.
- Never print a secret or ask a user to reveal one.
- Do not bypass a Pentect block. Explain the blocked content or unsupported
  surface and let the user choose a documented compatibility setting.
- Do not assume that remote or cloud agents use the local Pentect gateway.

Use `pentect doctor` to check the installation and `pentect log --once --tail
100` for bounded, value-free diagnostics. Product support and limits are documented at
https://pentect.dev/reference/compatibility/.
