# @pentect/pi

Run [Pi](https://github.com/badlogic/pi-mono) through Pentect's local HTTP
protection without changing Pi's saved configuration.

```sh
npx @pentect/pi --model openai/gpt-5
```

For a permanent command:

```sh
npm install --global @pentect/pi
pentect-pi --model openai/gpt-5
```

The package installs matching Pentect and Pi versions. It is a small launcher,
not a prompt hook: requests go through the same loopback gateway as
`pentect pi`.
