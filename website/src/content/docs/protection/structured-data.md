---
title: Structured data
description: Preserve useful labels while masking secrets in common configuration formats.
---

Pentect uses syntax and surrounding structure when it can. This produces more
useful handles than treating every detected value as a generic secret.

```dotenv
RUNPOD_API_KEY=<<RUNPOD_API_KEY_6b1275e3e3fadb9f>>
KAGGLE_API_TOKEN=<<KAGGLE_API_TOKEN_039fe674477b5763>>
```

## Recognized sources

Built-in structured detection covers common forms including:

- dotenv files, including comments and mildly malformed assignments
- Terraform variables and values
- Kubernetes Secrets and kubeconfig data
- AWS, npm, and PyPI configuration
- JSON and other recognized key/value structures

The label comes from the structure when the structure identifies the field. A
dotenv assignment, Terraform attribute, Kubernetes Secret key, and JSON object
key can therefore keep a useful name:

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

Comments, quoting, whitespace, and mildly malformed dotenv assignments are
handled without requiring a perfect parser round trip. Values that are empty,
comments, or clearly non-sensitive remain readable.

## When detectors disagree

Detection results can overlap. Pentect resolves overlap using structural label
evidence in this order:

1. A label established by the containing format, such as a dotenv or Kubernetes key.
2. Higher detector confidence.
3. A detection that covers the complete sensitive value.
4. A more specific built-in detector.
5. A canonical `SECRET` or `PII` label when equally credible labels still conflict.

Overlapping spans become one masked union and one handle. Edge-adjacent values
remain separate. The result does not depend on plugin execution order.

## Mask from a pipeline

```sh
cat .env | pentect mask
cat terraform.tfvars | pentect mask
```

PowerShell:

```powershell
Get-Content .env -Raw | pentect mask
```

`pentect mask` reads standard input and writes transformed text to standard
output, so it composes with existing tools. It does not need a format flag;
Pentect recognizes supported structure from the input itself.
