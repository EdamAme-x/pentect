# Structured secret sources

Pentect uses source structure only when it can identify the format with high
confidence. A structural key becomes the handle label; it never changes the
handle's underlying value or recovery behavior.

## Supported sources

| Source | Recognition | Masking rule |
| --- | --- | --- |
| dotenv | `.env*`, `*.env`, high-confidence dotenv content | every parsed value |
| Cloudflare | `.dev.vars*` | every parsed value |
| Firebase | `.secret.local`, `*.secret.local` | every parsed value |
| GitHub Actions | runner `set_env_*` files, including delimiter-based multiline values | every parsed value |
| AWS | `.aws/credentials`, sensitive fields in `.aws/config` | credential values only |
| npm | `.npmrc` | scoped auth values only |
| Python packaging | `.pypirc` | passwords/tokens only |
| Kubernetes Secret | YAML or JSON `kind: Secret`, `data` and `stringData` | every schema-defined secret value |
| kubeconfig | `kubeconfig` or `.kube/config` | token, password, and client private-key data |
| Docker/Kubernetes secret files | standard runtime mounts, `secrets/` directories, `*.secret` | complete file as one value |
| Git credential store | plaintext credential URLs | credential portion of each URL |
| Terraform | `*.tfvars`, `*.auto.tfvars`, JSON state `sensitive_values` | detected or explicitly sensitive values |
| generic config | YAML, TOML, INI, properties, and conf files | detected sensitive values only |

The parser preserves assignment keys, separators, quotes, comments, and UTF-8
boundaries. YAML block scalars and GitHub environment-file multiline values are
treated as one reversible value.

## Detection order

1. An explicit source schema or standard secret mount.
2. An official filename convention.
3. A high-confidence content signature.
4. Normal CredSweeper and Pentect detection.

An unknown or malformed format remains ordinary text. Pentect does not infer
that every value in an arbitrary configuration file is secret.

Tools may use arbitrary dotenv paths. `pentect read --kind env PATH` is the
explicit override when neither provenance nor content is sufficient;
`--kind structured` selects the conservative structured-config parser, and
`--kind secret` treats an explicitly supplied one-secret file as one value.
