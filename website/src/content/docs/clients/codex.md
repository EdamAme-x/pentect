---
title: Codex
description: Run Codex CLI and Codex App through Pentect.
---

import { Tabs, TabItem, Aside } from '@astrojs/starlight/components';

<Tabs>
  <TabItem label="CLI">
    ```text
    pentect codex
    ```

    Arguments after `codex` are forwarded to the Codex CLI.
  </TabItem>
  <TabItem label="App">
    ```text
    pentect codex app
    ```

    This launches the installed desktop app with Pentect routing for that app
    process. It does not permanently change the app's global configuration.
  </TabItem>
</Tabs>

## Protected flow

Pentect inserts a local Responses-compatible gateway for the launched client.
It protects supported prompt content, tool results, file inputs, and completed
tool-call arguments while preserving streaming responses.

## Existing providers

Existing Codex provider configuration is retained as the upstream when its wire
protocol is supported. You can also select an upstream for one launch:

```text
pentect codex --upstream http://127.0.0.1:8080/openai/v1
```

<Aside type="caution">
  Codex App coverage applies to its supported Codex mode. Pentect does not claim
  protection for ChatGPT Chat, Work, Voice, or unknown future opaque routes.
</Aside>
