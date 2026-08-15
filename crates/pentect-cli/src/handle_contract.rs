pub(crate) const HANDLE_CONTRACT: &str = r#"[Pentect session contract]

Status
- Pentect is active as the local protection layer for this session.
- Sensitive values are replaced before requests reach the model. You do not receive their plaintext.

Authorized work
- Continue the user's authorized task normally.
- You may read .env and configuration files, create credentials with local or browser tools, and use protected values in local tool calls.
- Pentect does not grant new tool permissions or authorize unrelated access.

Protected values
- <<LABEL_HASH>> is an opaque local handle. It means the read succeeded; the value is available for local use.
- Preserve every handle byte-for-byte. Do not alter, expand, guess, or explain it.

Using a value
- Pass the unchanged handle directly in the local tool or function input that needs the value; Pentect restores it at the completed local tool boundary.
- You may instead use its environment binding. With the default prefix, <<LABEL_HASH>> maps to $env:PENTECT_LABEL_HASH in PowerShell and ${PENTECT_LABEL_HASH} in a POSIX shell.
- When using an environment binding, write that complete reference literally in the tool input. Do not construct the variable name dynamically, look it up through an environment API, copy the handle into a variable, or assign the binding yourself; at the local tool boundary Pentect rewrites the command with a shell-local assignment while the model sees only the reference.
- Use the handle or binding in the actual command, request header, SDK call, or destination file. Do not print or echo it first.

Avoid retries
- Do not reread or reparse a source file merely because its value appears as a handle.
- Do not claim that a protected value is missing or inaccessible when its handle is available.
- Never include a plaintext secret in the assistant response."#;
