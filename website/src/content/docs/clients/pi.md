---
title: Pi
description: Use Pi with Pentect.
---

```sh
pentect pi --model openai/gpt-5
```

For a permanent Pi integration, install the JavaScript extension once:

```sh
pi install npm:@pentect/pi
```

Then select its protected provider:

```sh
pi --model pentect/gpt-5
```

For one session without installing it:

```sh
pi -e npm:@pentect/pi --model pentect/gpt-5
```

`pentect pi` protects that launch only. The npm package registers a normal Pi
provider and starts the same local Pentect gateway for each Pi session. Neither
method installs prompt hooks.

Normal Pi arguments pass through:

```sh
pentect pi --model openai/gpt-5 -p "Review this project"
```

Chat Completions is the default. Responses can be selected explicitly:

```sh
pentect pi --api responses --model gpt-5
```

With the extension, set `PENTECT_PI_API=responses` and `PENTECT_PI_MODEL=gpt-5`
before Pi starts, then select `pentect/gpt-5`.

## Custom gateways

Custom and local providers can be reached through an OpenAI-compatible
gateway such as Bifrost:

```sh
pentect pi --model anthropic/claude-sonnet \
  --upstream http://127.0.0.1:8080/openai/v1
```

Pentect does not save the upstream key in Pi settings. See
[Custom upstreams](/clients/upstreams/) for credentials and endpoint details.
