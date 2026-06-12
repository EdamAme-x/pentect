# Pentect demo plan

## Demo objective

Show that Pentect lets an AI agent work with sensitive technical data without seeing raw secrets.

The demo should make the core loop obvious:

1. Mask sensitive local data.
2. Send only masked text to AI.
3. Let AI reason or produce a command using placeholders.
4. Resolve placeholders locally at execution time.
5. Remask any echoed secrets before returning output to AI.

## Demo 1: Debugging with masked project data

### Setup

Prepare a small project-like folder or prompt bundle containing:

- `.env` with an API key and database URL
- config with an internal endpoint
- log excerpt with an email and request token
- stack trace with a realistic error

### Flow

1. Run Pentect masking over the selected inputs.
2. Show the AI only the masked version.
3. Ask the AI to explain the failure and suggest a fix.
4. Show that secrets are absent while repeated placeholders preserve identity.

### Message

Pentect makes masked technical context still useful for debugging.

## Demo 2: Resolve-at-exec

### Setup

Use a harmless local command or local HTTP endpoint that requires a secret-like value.

The secret must be a test value, not a live credential.

### Flow

1. Give the AI masked config or masked command context.
2. Let the AI produce a command containing placeholders.
3. Resolve placeholders locally immediately before execution.
4. Execute the resolved command outside the AI-visible transcript.
5. Remask stdout/stderr before showing the result back to the AI.

### Message

The AI can operate on protected resources without receiving the underlying secret.

## Demo 3: HAR or HTTP trace analysis

### Setup

Prepare a HAR-like or HTTP trace sample containing:

- Authorization header
- cookie
- signed URL or query token
- email or account identifier
- status codes and error body

### Flow

1. Mask the trace.
2. Show that credentials and identifiers are hidden.
3. Ask the AI to identify the likely issue or next test.
4. Verify the trace remains structurally useful.

### Message

Pentect is useful for security and pentest workflows, but it is not limited to them.

## What not to demo first

- General legal-document anonymization
- Full enterprise DLP dashboards
- Browser extension paste prevention
- Image/OCR masking
- Free-form Japanese names as the headline capability

These can be future demos, but they do not best communicate Pentect's initial edge.

## Success criteria

The first public demo should prove three things.

1. The AI never sees the raw secret.
2. The AI can still do useful technical work.
3. Local reversible masking enables execution workflows that one-way redaction cannot.
