---
title: Zed
description: Run Zed agent and inline-assistant traffic through Pentect.
---

## Start

```sh
pentect zed
```

Pentect opens Zed with a temporary user-data directory and model setting. Your
normal Zed settings are not changed.

```sh
pentect zed --model gpt-5 ~/project
```

## Protected

- Zed Agent Panel requests using the temporary Pentect model
- Inline Assistant requests using that model
- Agent conversation compaction
- Text, supported images, tool results, and completed tool calls on those paths

## Not protected by this command

- Zed edit predictions
- External agents launched by Zed
- An existing Zed window started without `pentect zed`

Use `--upstream URL` for a compatible OpenAI gateway. A provider that uses a
different API shape needs its own adapter.
