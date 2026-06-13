# Pentect PII boundary

## Decision

Pentect should describe itself as an AI-era local reversible DLP kernel for
sensitive values, not as a general PII anonymizer.

This phrasing is intentional:

- DLP is useful because the user pain is "do not let sensitive data leave this
  boundary."
- Local reversible is the moat: mask before AI, resolve only at local execution,
  remask tool output before it returns to the AI transcript.
- Kernel keeps the scope honest: core provides deterministic masking primitives;
  adapters provide browser hooks, agent hooks, storage, execution policy, and UI.

Avoid claiming to be a complete enterprise DLP product. That would imply policy
management, endpoint coverage, audit pipelines, admin controls, file scanners,
and network enforcement that the core does not provide.

## What core owns

Core owns PII that can be detected from value shape, checksum, codec structure,
or tight technical context.

Examples:

- email addresses
- phone numbers
- card numbers
- IBAN, BIC, account-like finance identifiers
- passports and national identifiers with strong or contextual validation
- usernames, tokens, URLs, cookies, headers, credentials, and database URLs

These are aligned with the main AI-agent workflow because they appear in logs,
configs, tickets, API examples, HAR traces, and command output.

## What core does not promise

Core does not promise full free-text PII recall.

Examples:

- person names
- street addresses
- organization names
- job titles
- locations mentioned as prose
- titles, ages, vague dates, and other semantic references

These require semantic interpretation and should live in optional NER sidecars,
local LLM audit, or project-specific packs. They can be supported, but they
should not redefine the core.

## Product model

The intended layering is:

1. `pentect-core`: deterministic reversible masking, resolve, remask, and
   value-free reporting.
2. Semantic layer: optional NER/local model detectors for free-text PII.
3. Adapter layer: Codex/Claude/Gemini hooks, browser extension, CLI wrapper,
   session storage, execution gating, and audit UX.

The adapter can call the whole product "AI-era DLP." The core should remain a
small, testable masking kernel.

## Evaluation split

Report PII performance in two buckets:

- `structured PII`: core-relevant labels such as email, phone, card, IBAN,
  passport, account number, social/tax number, and usernames.
- `semantic PII`: NER-relevant labels such as names, addresses, organizations,
  locations, titles, dates, and times.

Do not merge these into one score when deciding whether core is good. A single
PII recall number makes the product look worse for the wrong reason and hides
which layer needs work.
