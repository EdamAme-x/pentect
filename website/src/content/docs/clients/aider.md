---
title: Aider
description: Launch Aider through Pentect's local OpenAI-compatible gateway.
---

## Launch

```sh
pentect aider
```

Pentect starts a local gateway, points Aider's main, weak, and editor models at
it, then removes the gateway when Aider exits. Your Aider config and `.env`
files are not rewritten.

Choose a model or forward normal Aider arguments directly:

```sh
pentect aider --model gpt-5 README.md
```

Use an existing OpenAI-compatible upstream behind Pentect with:

```sh
pentect aider --upstream http://127.0.0.1:8080/v1
```

The initial adapter covers Aider's OpenAI-compatible chat path. Anthropic and
other provider families are separate compatibility surfaces and are not
claimed by this command yet.
