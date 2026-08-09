---
title: Zed
description: Use Zed with Pentect.
---

## Start

```sh
pentect zed
```

Pentect protects this Zed session only. Your saved Zed settings are not
changed.

```sh
pentect zed --model gpt-5 ~/project
```

## Protected

- Zed Agent Panel requests using the Pentect model
- Inline Assistant requests using that model
- Agent conversation compaction
- Text, supported images, tool results, and completed tool calls on those paths

## Not protected by this command

- Zed edit predictions
- External agents launched by Zed
- An existing Zed window started without `pentect zed`

Use `--upstream URL` for a compatible OpenAI gateway. A provider that uses a
different API shape needs its own adapter.
