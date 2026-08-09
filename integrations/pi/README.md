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

The JavaScript extension only manages Pi's provider lifecycle. Detection,
handles, plugins, and network forwarding remain inside the Pentect binary.
