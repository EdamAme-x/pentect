---
title: Aider
description: Use Aider with Pentect.
---

## Start

```sh
pentect aider
```

Pentect protects this Aider session only. Your saved Aider settings are not
changed.

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
