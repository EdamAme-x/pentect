---
title: Quick start
description: Protect a real Codex or Claude session in a few commands.
---

import { Steps, Aside } from '@astrojs/starlight/components';

<Steps>
1. Check that Pentect can find your client.

   ```text
   pentect doctor
   ```

2. Launch the client through Pentect.

   ```text
   pentect codex
   # or
   pentect claude
   ```

3. Work normally.

   Ask the agent to read a local configuration file or perform a task that
   requires a credential. Protected values appear to the model as handles such
   as `<<DATABASE_URL_4ce8a3b0a6f64e12>>`.

4. Watch local protection events when needed.

   ```text
   pentect log
   ```
</Steps>

## Try masking without an agent

```sh
cat .env | pentect mask
cat terraform.tfvars | pentect mask
```

PowerShell:

```powershell
Get-Content .env -Raw | pentect mask
```

The output contains reusable handles. Plaintext is not printed back to the
terminal.

<Aside type="tip">
  Pentect does not create a permanent global proxy. `pentect codex` and
  `pentect claude` protect only the client process launched by that command.
</Aside>
