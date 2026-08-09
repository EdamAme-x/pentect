---
title: Pi
description: Run Pi through a temporary Pentect provider.
---

```sh
pentect pi --model openai/gpt-5
```

Or install Pi and the matching Pentect release together:

```sh
npx @pentect/pi --model openai/gpt-5
```

Pentect protects this Pi launch only. It does not install prompt hooks or edit
Pi settings.

Normal Pi arguments pass through:

```sh
pentect pi --model openai/gpt-5 -p "Review this project"
```

Chat Completions is the default. Responses can be selected explicitly:

```sh
pentect pi --api responses --model gpt-5
```

## Custom gateways

Custom and local providers can be reached through an OpenAI-compatible
gateway such as Bifrost:

```sh
pentect pi --model anthropic/claude-sonnet \
  --upstream http://127.0.0.1:8080/openai/v1
```

The temporary provider contains no API key or gateway token. See
[Custom upstreams](/clients/upstreams/) for credentials and endpoint details.
