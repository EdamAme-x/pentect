# Pentect use cases

## Use case 1: AI debugging with technical files

技術者が `.env`、設定、ログ、README、stack trace、コード断片を AI に渡してデバッグ相談する。

### Input examples

- `.env` with API keys, DB URL, OAuth client secret
- Application logs containing request IDs, email addresses, tokens
- Config files containing internal endpoints and credentials
- Stack traces with paths, hostnames, and request context

### What Pentect must hide

- API keys, tokens, passwords, private keys
- DB connection strings and credential-bearing URLs
- Authorization headers, cookies, session IDs
- Structured PII such as email, phone, card, IBAN, national IDs

### What Pentect should preserve

- File structure and syntax
- Error messages
- Status codes, HTTP methods, endpoint shape
- Non-secret variable names and configuration keys
- Enough stable identity to let the AI correlate repeated values

### Success condition

The AI can explain the likely bug or suggest a fix without seeing raw secrets, and no masked secret appears in the prompt sent to the AI.

## Use case 2: Agent tool-use without exposing secrets

AI agent reads masked project data and proposes commands. The agent sees placeholders, not raw values. The local adapter resolves placeholders only immediately before execution, then remasks command output.

### Input examples

- `curl -H "Authorization: Bearer <<TOKEN_...>>" ...`
- `psql "$DATABASE_URL"` generated from masked config
- Cloud CLI commands using masked API keys or account IDs

### What Pentect must provide

- Stable placeholders for repeated values
- A recovery map held locally
- A resolve operation before execution
- A remask operation on stdout/stderr/tool results

### Success condition

The command can run with real local credentials, but the AI transcript and returned tool output do not contain the original secret.

## Use case 3: Security and pentest workflow

Security-oriented users give AI logs, HAR traces, requests, responses, and reproduction steps from a real or staging system.

### Input examples

- HAR export from a logged-in session
- HTTP request/response traces
- Reproduction steps containing session cookies
- Scanner output containing endpoints, tokens, emails, or IDs

### What Pentect must hide

- Cookies and Authorization headers
- Query tokens and signed URLs
- Session IDs, CSRF tokens, API keys
- Customer identifiers and structured PII

### What Pentect should preserve

- Request method, path shape, status code, timing, redirect structure
- Parameter names, header names, and content type
- Vulnerability-relevant versions and error messages by default

### Success condition

The AI can reason about the security issue or reproduce the investigation flow without receiving raw credentials or customer data.

## Use case 4: Optional semantic PII protection

Some users need person names, organization names, addresses, or locations masked in prose. This is supported as an optional layer, not as the core promise.

### Input examples

- Support tickets
- Meeting notes
- Legal or business documents mixed into a technical prompt

### Boundary

Core deterministic masking does not claim full semantic PII recall. Semantic PII belongs in NER sidecars, local LLM audit, or user packs.

### Success condition

When enabled, the semantic layer adds useful protection without weakening the deterministic core or changing the core positioning.

## Prioritization

The first three use cases are primary. They all share the same product shape: local reversible masking for AI workflows over technical data.

The fourth use case is secondary. It should not force Pentect to become a general-purpose anonymizer.
