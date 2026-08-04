---
title: Security model
description: Trust boundaries, defaults, guarantees, and explicit limitations.
---

import { Aside } from '@astrojs/starlight/components';

Pentect protects supported content at the boundary between a local AI client
and a model provider. It assumes the local user and explicitly authorized local
tools are trusted to use the credentials they already possess.

## Security properties

- Sensitive values are replaced before supported provider requests leave the
  local process boundary.
- Recovery data stays in the local Pentect session and is not placed in the
  model request.
- Known handles resolve only at supported trusted client tool boundaries.
- Tool output is masked before it returns to the provider.
- Unknown provider formats and unsupported content are blocked by default.
- Wasm plugins run without WASI, filesystem, environment, process, or raw
  socket access.

## What Pentect does not guarantee

- Perfect detection of every secret or PII format
- Safety after a trusted local tool uses a credential against an external
  service
- Protection for unsupported clients, opaque transports, or future routes
- Replacement for least privilege, credential rotation, endpoint controls, or
  client sandboxing

## Compatibility mode

Unknown provider formats default to an error. A user can explicitly relax this
only in the user-level configuration:

```toml
[compatibility]
unknown_formats = "ignore"
```

Project configuration cannot weaken this setting. This prevents a repository
from silently choosing a less protective policy.

<Aside type="danger">
  Compatibility mode can allow content Pentect does not understand to reach an
  upstream. Do not enable it merely to suppress an unexplained error.
</Aside>

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Follow the private
reporting process in the repository's
[security policy](https://github.com/EdamAme-x/pentect/security/policy).
