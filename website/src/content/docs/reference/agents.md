---
title: Instructions for agents
description: A short set of rules for tools that run through Pentect.
---

Pentect replaces sensitive values with opaque handles before a request reaches
the model. A handle looks like `<<API_KEY_ab12...>>`.

## Rules

- Copy handles exactly. Do not edit, expand, guess, or explain them.
- Use a handle only in a local tool call that needs its value.
- Never print a secret or ask the user to reveal one.
- Do not bypass a Pentect block. Report the unsupported content or surface, and
  let the user choose a documented compatibility setting.
- Do not assume that a remote or cloud agent uses the local Pentect gateway.

Use `pentect doctor` to check the installation and `pentect log` for
diagnostics that do not contain secret values.

The same instructions are available in the repository's
[`AGENTS.md`](https://github.com/EdamAme-x/pentect/blob/main/AGENTS.md).
