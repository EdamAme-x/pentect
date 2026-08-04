---
title: How it works
description: Follow a sensitive value from local input to a trusted tool call.
---

import { Steps, Aside } from '@astrojs/starlight/components';

Pentect sits between a supported AI client and its model provider. It transforms
supported request and response structures without replacing the client UI.

<Steps>
1. **Detect locally**

   Pentect inspects prompts, supported tool results, configuration formats,
   uploads, and images before protected content crosses the provider boundary.

2. **Replace with an opaque handle**

   ```text
   KAGGLE_API_TOKEN=KGAT_example
   KAGGLE_API_TOKEN=<<KAGGLE_API_TOKEN_85268c441f88c284>>
   ```

   Labels may come from structure, such as a dotenv key. The keyed hash gives
   the same protected value a stable reference within the configured scope.

3. **Let the model use the reference**

   The model can reason about the named value and place the handle in a tool
   call without learning its plaintext.

4. **Resolve only at the trusted boundary**

   Pentect resolves known handles immediately before the local client executes
   a completed tool call. Unknown handle-shaped text remains inert.

5. **Mask results on the way back**

   Tool output is inspected before it returns to the provider, preventing a
   locally restored value from simply leaking back in stdout or a file read.
</Steps>

## Why handles instead of `[REDACTED]`?

Plain redaction removes both the value and its identity. A Pentect handle keeps
enough context for an agent to finish work while preserving the security
boundary.

<Aside type="caution">
  A handle is a reference, not an authorization decision. If a local tool is
  allowed to use the credential, it can act with that credential's privileges.
  Use scoped, revocable credentials and narrow tool permissions.
</Aside>
