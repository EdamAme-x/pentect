---
title: Antigravity CLI
description: Run the official Antigravity CLI through Pentect.
---

Launch the official `agy` command through Pentect:

```sh
pentect antigravity
```

`pentect agy` is a shorter alias. Normal Antigravity arguments pass through:

```sh
pentect agy --print "Review this project"
```

Pentect gives only the child process a temporary `CLOUD_CODE_URL`. The official
CLI keeps its normal Google sign-in and sends Cloud Code model requests through
the local Pentect gateway. Pentect does not edit Antigravity settings or install
a certificate.

Pentect checks prompts, function results, inline text and images, streaming
responses, and function calls. A known handle stays visible to the model and is
restored only inside a function call that returns to the local client. Unknown
Cloud Code routes and content parts are blocked by default.

## Existing Cloud Code endpoint

If `CLOUD_CODE_URL` already points to a compatible endpoint, Pentect uses it as
the upstream and places the local gateway in front of it. You can also select an
endpoint for one launch:

```sh
pentect antigravity --upstream https://cloud-code.example
```

Add a gateway credential without putting its value in command history:

```sh
PENTECT_GATEWAY_AUTH="Bearer example" \
  pentect antigravity \
  --upstream https://cloud-code.example \
  --upstream-header-env Authorization=PENTECT_GATEWAY_AUTH
```

The source environment variable is removed from the `agy` process. The header
is added only by Pentect when it contacts the selected upstream.

Pentect protects the Cloud Code model boundary. Google sign-in and unrelated
Antigravity services continue to use their normal endpoints.
