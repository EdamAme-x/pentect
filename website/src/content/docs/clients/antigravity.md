---
title: Antigravity CLI
description: Use Antigravity CLI with Pentect.
---

Start a protected Antigravity CLI session:

```sh
pentect antigravity
```

Google sign-in works as usual. Pentect changes routing only for the launched
process and does not edit Antigravity settings or install a certificate.

## Pass Antigravity arguments

`pentect agy` is a shorter alias. Normal Antigravity arguments pass through:

```sh
pentect agy --print "Review this project"
```

## What Pentect protects

Pentect checks prompts, function results, inline text and images, streaming
responses, and function calls. A known handle stays visible to the model and is
restored only inside a function call that returns to the local client. Unknown
Cloud Code routes and content parts are blocked by default.

Using another Cloud Code-compatible endpoint is optional. See
[Custom upstreams](/clients/upstreams/#antigravity-and-cloud-code) for endpoint
selection and gateway credentials.
