# Example regex plugin

This is the smallest complete Pentect plugin. It uses only `plugin.toml` and
needs no binary, setup script, or network access.

```sh
pentect plugins test ./plugins/example-regex
echo "case ACME-12345678" | pentect mask --plugins ./plugins/example-regex
```

Copy the directory, then change the name, description, label, and pattern. See
the [plugin guide](https://pentect.dev/plugins/build/) and
[manifest reference](https://pentect.dev/plugins/manifest/) for all fields.
