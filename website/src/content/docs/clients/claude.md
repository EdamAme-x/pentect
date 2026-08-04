---
title: Claude
description: Run Claude Code and supported Claude Desktop routes through Pentect.
---

import { Tabs, TabItem, Aside } from '@astrojs/starlight/components';

<Tabs>
  <TabItem label="Claude Code">
    ```text
    pentect claude
    ```

    Arguments after `claude` are forwarded to Claude Code.
  </TabItem>
  <TabItem label="Claude Desktop">
    ```text
    pentect claude app
    ```

    Pentect launches the installed app with a local Messages-compatible gateway
    and an isolated certificate configuration for that process.
  </TabItem>
</Tabs>

## Protected flow

Supported Chat, attachment, and Claude Code traffic is inspected before it
reaches the Anthropic-compatible upstream. Completed local tool calls can use
opaque handles without exposing their plaintext to the model.

```text
pentect claude --upstream http://127.0.0.1:8080/anthropic
```

<Aside type="caution">
  Pentect does not claim coverage for remote Cowork execution, Voice,
  experimental binary transports, or unknown future opaque routes. Unsupported
  formats follow the configured compatibility policy.
</Aside>
