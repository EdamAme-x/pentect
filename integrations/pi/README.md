# @pentect/pi

Use [Pi](https://github.com/badlogic/pi-mono) with Pentect as a normal Pi
extension. The extension starts Pentect's local gateway and registers one
protected provider for the session.

```sh
pi install npm:@pentect/pi
pi --model pentect/gpt-5
```

To try it without installing:

```sh
pi -e npm:@pentect/pi --model pentect/gpt-5
```

Set `PENTECT_PI_MODEL` before Pi starts to expose a different model. Set
`PENTECT_PI_API=responses` for the OpenAI Responses API. `OPENAI_BASE_URL` and
`OPENAI_API_KEY` configure the upstream.

For a custom upstream whose model limits differ from the defaults, set
`PENTECT_PI_CONTEXT_WINDOW`, `PENTECT_PI_MAX_TOKENS`,
`PENTECT_PI_INPUTS=text`, or `PENTECT_PI_REASONING=true|false`. Invalid values
stop startup instead of advertising incorrect capabilities to Pi.

The JavaScript extension only manages Pi's provider lifecycle. Detection,
handles, plugins, and network forwarding remain inside the Pentect binary.
