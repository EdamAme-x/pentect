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

Detection results can overlap. Pentect resolves overlap using structural label
evidence, detector confidence, covered range, and detector specificity. Equally
credible conflicting secret labels fall back to a generic `SECRET`; PII labels
fall back to `PII`.

## Mask from a pipeline

```sh
cat .env | pentect mask
cat terraform.tfvars | pentect mask
```

PowerShell:

```powershell
Get-Content .env -Raw | pentect mask
```

No `--kind` flag is required for ordinary input. Pentect infers the format from
the source or content where available.
