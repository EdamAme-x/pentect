---
title: Structured data
description: Keep useful field names while masking secrets in common config files.
---

Pentect uses file syntax and field names when possible. This creates clearer
handles than using `SECRET` for every value.

```dotenv
RUNPOD_API_KEY=<<RUNPOD_API_KEY_6b1275e3e3fadb9f>>
KAGGLE_API_TOKEN=<<KAGGLE_API_TOKEN_039fe674477b5763>>
```

## Recognized sources

Built-in checks support common formats, including:

- dotenv files, including comments and small syntax errors
- Terraform variables and values
- Kubernetes Secrets and kubeconfig data
- AWS, npm, and PyPI configuration
- JSON and other recognized key/value structures

When a file clearly names a field, Pentect uses that name for the handle. This
works with dotenv keys, Terraform fields, Kubernetes Secret keys, and JSON keys:

::: code-group

```dotenv [dotenv]
DATABASE_URL=<<DATABASE_URL_4ce8a3b0a6f64e12>>
```

```hcl [Terraform]
api_token = "<<API_TOKEN_85268c441f88c284>>"
```

```yaml [Kubernetes]
stringData:
  password: <<PASSWORD_f013c9d470d12b11>>
```

```json [JSON]
{"client_secret":"<<CLIENT_SECRET_5705e45cbb897a52>>"}
```

:::

Pentect handles comments, quotes, spaces, and small dotenv syntax errors. Empty
values, comments, and values that are clearly safe stay visible.

## When detectors disagree

Two checks can find the same text. Pentect chooses the label in this order:

1. A field name from the file format, such as a dotenv or Kubernetes key.
2. The result with higher confidence.
3. The result that covers the full sensitive value.
4. The more specific built-in check.
5. `SECRET` or `PII` when two equally strong labels still disagree.

Overlapping results become one handle that covers the full area. Values that
only touch at their edges stay separate. Plugin order does not change the result.

## Mask from a pipeline

```sh
cat .env | pentect mask
cat terraform.tfvars | pentect mask
```

PowerShell:

```powershell
Get-Content .env -Raw | pentect mask
```

`pentect mask` reads standard input and writes protected text to standard
output. You can use it in a normal pipe. Pentect finds the format on its own,
so you do not need a format option.
