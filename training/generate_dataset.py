"""Generate synthetic training samples that stress LLM-only detection.

The templates here are deliberately chosen to be *hard for regex-based detectors*:
- Custom in-house token formats that don't match known patterns (JWT/AWS/ghp_).
- Plain variable-name-less credentials assigned to opaque names (x, val, tmp).
- Internal hostnames without public TLD hints (single-label, kebab-case).
- Credentials embedded in code-like contexts (Python/TS/YAML fragments).
- Context-dependent user/resource identifiers (e.g., "customer #8842").
- Person names in prose (e.g., Japanese/English report sentences).

Regex can cover most of the "easy" cases (see engine/detectors/rule.py). This
dataset targets what regex *cannot* systematically catch, so an FT'd LLM has a
reason to exist.

Usage:
    python -m training.generate_dataset --out training/data/train.jsonl --n 800
"""
from __future__ import annotations

import argparse
import json
import random
import string
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Sample:
    input: str
    spans: list[dict]


def _rand(alphabet: str, n: int) -> str:
    return "".join(random.choices(alphabet, k=n))


# --- "hard" value generators (LLM-only territory) ----------------------------

def _gen_custom_token() -> str:
    """In-house token format: prefix + segments, nothing standard."""
    prefixes = ["TK", "HX", "CORP", "Z9", "IGT", "ZN"]
    segs = [_rand(string.ascii_uppercase + string.digits, random.randint(4, 8)) for _ in range(random.randint(2, 4))]
    return f"{random.choice(prefixes)}-{'-'.join(segs)}"


def _gen_opaque_cred() -> str:
    """Looks like random gibberish with no hint in the variable name."""
    return _rand(string.ascii_letters + string.digits, random.randint(14, 28))


def _gen_bare_internal_host() -> str:
    """Single-label or kebab-case internal service name without public TLD."""
    names = [
        "billing-svc", "auth-gateway", "orders", "warehouse-api", "ledger",
        "payments-core", "kyc-service", "reporting", "inventory", "fulfillment",
        "shipping-core", "tax-calc", "risk-engine", "coupon-svc", "pricing",
        "cart-api", "session-store", "invoice-gen", "refund-core", "loyalty",
        "kyc-v3", "audit-trail", "catalog", "search-core", "rec-engine",
        "media-proxy", "cdn-origin", "doc-store", "batch-runner", "cron-svc",
    ]
    return random.choice(names)


def _gen_inline_ip_no_context() -> str:
    """Private IP placed where a regex might not anchor (inside identifier-ish text)."""
    return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _gen_resource_id() -> str:
    return str(random.randint(1000, 999999))


def _gen_person_name_en() -> str:
    first = random.choice(["Alice", "Bob", "Carol", "Dan", "Eve", "Frank", "Grace", "Hank"])
    last = random.choice(["Smith", "Johnson", "Brown", "Davis", "Miller", "Wilson"])
    return f"{first} {last}"


def _gen_email() -> str:
    user = random.choice(["alice", "bob", "carol", "haruko", "ren", "kenji", "sakura"])
    domain = random.choice([
        "corp.local", "corp.example", "example.com", "internal.local",
        "company.co.jp", "ops.local",
    ])
    return f"{user}@{domain}"


def _gen_person_name_ja() -> str:
    # romanised Japanese-style names (kept ASCII to simplify tokenisation in PoC)
    firsts = ["Taro", "Hanako", "Yuki", "Ren", "Sakura", "Kenji", "Aoi"]
    lasts = ["Tanaka", "Sato", "Suzuki", "Takahashi", "Ito", "Watanabe"]
    return f"{random.choice(lasts)} {random.choice(firsts)}"


# --- templates: each produces a (text, spans) pair --------------------------

_TEMPLATES: list = [
    # 1. custom token in code-like assignment, no "secret=" hint
    ("config.token = \"{tok}\"  # provisioned by platform team", [("tok", "CREDENTIAL")]),
    ("CORP_TOKEN_V2: {tok}", [("tok", "CREDENTIAL")]),
    ("headers['X-Corp-Auth'] = '{tok}'", [("tok", "CREDENTIAL")]),

    # 2. opaque credential assigned to meaningless variable
    ("x = \"{opq}\"  # used by the billing worker", [("opq", "CREDENTIAL")]),
    ("val := '{opq}'  // injected at boot", [("opq", "CREDENTIAL")]),
    ("tmp = \"{opq}\"; sendAuth(tmp)", [("opq", "CREDENTIAL")]),

    # 3. bare internal host, no scheme, no public TLD
    ("connected to {host}:5432 successfully", [("host", "INTERNAL_URL")]),
    ("upstream host = {host}  # k8s service dns", [("host", "INTERNAL_URL")]),
    ("Retrying request to {host} after timeout", [("host", "INTERNAL_URL")]),

    # 4. cred in code-like context with identifier-looking constant name
    ("API_KEY: str = \"{opq}\"  # loaded from vault", [("opq", "CREDENTIAL")]),
    ("const SERVICE_SECRET = '{opq}';", [("opq", "CREDENTIAL")]),

    # 5. context-dependent resource id in prose -- many wordings, since
    # the hard_val set has a wide variety of "ticket #N" / "customer #N"
    # / "incident #N" sentences and the model needs broad coverage.
    ("customer #{rid} reported the incident", [("rid", "USER_ID")]),
    ("See ticket #{rid} for the stack trace", [("rid", "USER_ID")]),
    ("issue {rid} was closed after the rollback", [("rid", "USER_ID")]),
    ("Customer #{rid} was exposed because {name} accidentally shared the link",
     [("rid", "USER_ID"), ("name", "PII_NAME")]),
    ("At 10:42 JST, {name} bumped ticket #{rid} from P3 to P1 after confirming the bug",
     [("name", "PII_NAME"), ("rid", "USER_ID")]),
    ("SRE memo: チケット #{rid} の root cause は {host} の設定漏れ。assigned to {name}",
     [("rid", "USER_ID"), ("host", "INTERNAL_URL"), ("name", "PII_NAME")]),
    ("ステージング環境 {host} ({ip}) でのみ再現したため、本番影響はなしと判断。担当: {name_ja}、チケット #{rid}",
     [("host", "INTERNAL_URL"), ("ip", "INTERNAL_IP"), ("name_ja", "PII_NAME"), ("rid", "USER_ID")]),
    ("Linked issue #{rid}: customer reported by {name} on the staging cluster",
     [("rid", "USER_ID"), ("name", "PII_NAME")]),
    ("Postmortem #{rid} owner={name}, target={host}, severity=high",
     [("rid", "USER_ID"), ("name", "PII_NAME"), ("host", "INTERNAL_URL")]),
    ("incident-{rid} closed: rollback executed by {name} at 03:14 JST",
     [("rid", "USER_ID"), ("name", "PII_NAME")]),
    ("Customer-{rid} requested a refund via support: agent {name} handled it",
     [("rid", "USER_ID"), ("name", "PII_NAME")]),
    ("user #{rid} flagged for fraud review (analyst: {name})",
     [("rid", "USER_ID"), ("name", "PII_NAME")]),
    ("PR #{rid} merged into main by {name}, deploys to {host}",
     [("rid", "USER_ID"), ("name", "PII_NAME"), ("host", "INTERNAL_URL")]),
    ("Bug #{rid} ({host} 5xx spike) — assignee: {name}",
     [("rid", "USER_ID"), ("host", "INTERNAL_URL"), ("name", "PII_NAME")]),
    ("Reopening ticket #{rid}: {name} cannot log in from {host}",
     [("rid", "USER_ID"), ("name", "PII_NAME"), ("host", "INTERNAL_URL")]),
    ("Closed: Issue #{rid} root caused to {host} timeout (oncall: {name})",
     [("rid", "USER_ID"), ("host", "INTERNAL_URL"), ("name", "PII_NAME")]),
    ("Order #{rid} was refunded after customer {name} reported double charge",
     [("rid", "USER_ID"), ("name", "PII_NAME")]),
    ("チケット #{rid} 担当: {name_ja}",
     [("rid", "USER_ID"), ("name_ja", "PII_NAME")]),
    ("障害番号 #{rid} の影響範囲: {host}",
     [("rid", "USER_ID"), ("host", "INTERNAL_URL")]),
    ("ご担当: {name_ja} (お問い合わせ番号: #{rid})",
     [("name_ja", "PII_NAME"), ("rid", "USER_ID")]),
    ("Ref: SLACK-{rid} reported by @{name} on #incidents",
     [("rid", "USER_ID"), ("name", "PII_NAME")]),
    ("[INC{rid}] {host} returned 502 for 5 minutes",
     [("rid", "USER_ID"), ("host", "INTERNAL_URL")]),
    ("PR-{rid}: refactor of {host} client (reviewer: {name})",
     [("rid", "USER_ID"), ("host", "INTERNAL_URL"), ("name", "PII_NAME")]),
    ("Tracking: pagerduty incident {rid} created by {name}",
     [("rid", "USER_ID"), ("name", "PII_NAME")]),

    # 6. person name in prose (PII_NAME)
    ("{name} confirmed the rollback at 03:12 JST", [("name", "PII_NAME")]),
    ("Reported by {name} after escalation from on-call", [("name", "PII_NAME")]),
    ("{name_ja}-san asked for access to the staging cluster", [("name_ja", "PII_NAME")]),

    # 7. mixed: bare host + opaque cred, no structured format
    (
        "proxy -> {host} with x-internal-token {opq} (expires 60m)",
        [("host", "INTERNAL_URL"), ("opq", "CREDENTIAL")],
    ),

    # 8. private IP with no surrounding quotes or JSON structure
    ("route add {ip} via gw-01 metric 10", [("ip", "INTERNAL_IP")]),
    ("node {host} ({ip}) joined the pool", [("host", "INTERNAL_URL"), ("ip", "INTERNAL_IP")]),

    # 9. custom token embedded mid-sentence
    (
        "the deploy used key {tok} issued by the platform ops for {name}",
        [("tok", "CREDENTIAL"), ("name", "PII_NAME")],
    ),

    # 10. resource id + person + host, report-style
    (
        "{name} opened #{rid} against {host} about the 500s",
        [("name", "PII_NAME"), ("rid", "USER_ID"), ("host", "INTERNAL_URL")],
    ),

    # 11. INTERNAL_URL in terraform / infra-as-code fragments
    (
        "resource \"kubernetes_service\" \"{host}\" {{ cluster_ip = \"None\" }}",
        [("host", "INTERNAL_URL")],
    ),
    (
        "backend_service_upstream({host}, retries=3)",
        [("host", "INTERNAL_URL")],
    ),
    (
        "dial tcp {host}:9092: connection refused",
        [("host", "INTERNAL_URL")],
    ),

    # 12. INTERNAL_URL in observability / metric names
    (
        "counter rpc_requests_total{{target=\"{host}\"}} 14820",
        [("host", "INTERNAL_URL")],
    ),
    (
        "span attribute upstream.service={host} attached to trace {rid}",
        [("host", "INTERNAL_URL"), ("rid", "USER_ID")],
    ),

    # 13. INTERNAL_URL in SQL / query-like text
    (
        "SELECT * FROM service_health WHERE name = '{host}' AND status = 'degraded'",
        [("host", "INTERNAL_URL")],
    ),

    # 14. INTERNAL_URL + host grouping (table-ish CSV row, not YAML)
    (
        "{host},prod,owner={name},last_deploy=2025-11-03",
        [("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),

    # 15. INTERNAL_URL in curl / shell one-liners
    (
        "curl -sSf http://{host}/healthz || echo 'down'",
        [("host", "INTERNAL_URL")],
    ),
    (
        "kubectl port-forward svc/{host} 8080:80 -n platform",
        [("host", "INTERNAL_URL")],
    ),

    # 16. INTERNAL_URL + CREDENTIAL in dockerfile / env-file
    (
        "ENV UPSTREAM={host} API_TOKEN={tok}",
        [("host", "INTERNAL_URL"), ("tok", "CREDENTIAL")],
    ),

    # 17. INTERNAL_URL in Japanese log without the hard_val vocabulary
    (
        "{host} へのリクエストが {rid} 回連続で失敗しました。担当 {name_ja} に共有済み。",
        [("host", "INTERNAL_URL"), ("rid", "USER_ID"), ("name_ja", "PII_NAME")],
    ),
    (
        "{name_ja} が {host} のレイテンシ悪化を調査中(token {opq} で再現)",
        [("name_ja", "PII_NAME"), ("host", "INTERNAL_URL"), ("opq", "CREDENTIAL")],
    ),

    # 18. INTERNAL_URL in HTTP-like trace lines (the format the FT model
    # mostly sees in HAR-derived inputs).
    (
        "GET http://{host}/api/v1/healthz -> 200 OK",
        [("host", "INTERNAL_URL")],
    ),
    (
        "POST http://{host}:{port}/internal/refresh-token -> 401",
        [("host", "INTERNAL_URL"), ("port", "INTERNAL_URL_PORT_IGNORE")],
    ),
    (
        "PUT http://{host}/admin/users/{rid} -> 204 No Content",
        [("host", "INTERNAL_URL"), ("rid", "USER_ID")],
    ),
    (
        "DELETE http://{host}/v2/orders/{rid}",
        [("host", "INTERNAL_URL"), ("rid", "USER_ID")],
    ),

    # 19. Hostname appears in dashboards / metrics / SLO labels.
    (
        "alert fired on service={host} severity=critical owner={name}",
        [("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),
    (
        "p99 latency = 312ms on {host} (last 5m)",
        [("host", "INTERNAL_URL")],
    ),
    (
        "rolled back deploy of {host} after error budget breach",
        [("host", "INTERNAL_URL")],
    ),

    # 20. Hostname in YAML / Helm / k8s manifests.
    (
        "  host: {host}\n  port: 5432\n  user: {name}",
        [("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),
    (
        "spec:\n  rules:\n    - host: {host}\n      http:\n        paths: []",
        [("host", "INTERNAL_URL")],
    ),
    (
        "image: registry.{host}/team/cart:{rid}",
        [("host", "INTERNAL_URL"), ("rid", "USER_ID")],
    ),

    # 21. Hostname in TOML / .env / Dockerfile / shell history.
    (
        "DATABASE_URL=postgres://{name}:{tok}@{host}:5432/main",
        [("name", "PII_NAME"), ("tok", "CREDENTIAL"), ("host", "INTERNAL_URL")],
    ),
    (
        "REDIS_HOST={host}\nREDIS_PASSWORD={opq}",
        [("host", "INTERNAL_URL"), ("opq", "CREDENTIAL")],
    ),
    (
        "ENV WORKER_QUEUE={host} WORKER_TOKEN={tok}",
        [("host", "INTERNAL_URL"), ("tok", "CREDENTIAL")],
    ),
    (
        "history: ssh {name}@{host} 'systemctl restart cart'",
        [("name", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),

    # 22. Hostname in commit messages / PR descriptions / runbook prose.
    (
        "fix: timeout when {host} returns 502 during checkout",
        [("host", "INTERNAL_URL")],
    ),
    (
        "Runbook: if {host} sheds load, page {name} via the on-call rota.",
        [("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),
    (
        "Postmortem: {name} found {host} exhausting connections; restart fixed it.",
        [("name", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),

    # 23. JS bundle / inline config-style fragments where ids and hosts appear
    # tightly packed (mirrors the patterns we saw leaking from /rest/admin/...).
    (
        "config={{apiBase:'http://{host}',clientId:'{tok}',admin:'{email}'}}",
        [("host", "INTERNAL_URL"), ("tok", "CREDENTIAL"), ("email", "PII_EMAIL")],
    ),
    (
        "window.PUBLIC_CFG={{host:\"{host}\",userId:{rid}}}",
        [("host", "INTERNAL_URL"), ("rid", "USER_ID")],
    ),

    # 24. Bearer / Basic auth in raw HTTP header form.
    (
        "Authorization: Bearer {tok}",
        [("tok", "CREDENTIAL")],
    ),
    (
        "Authorization: Basic {opq}",
        [("opq", "CREDENTIAL")],
    ),
    (
        "Cookie: session={opq}; Path=/; HttpOnly",
        [("opq", "CREDENTIAL")],
    ),
    (
        "Set-Cookie: PHPSESSID={opq}; Secure",
        [("opq", "CREDENTIAL")],
    ),

    # 25. Cred + host together in CI/CD logs.
    (
        "+ curl -H 'X-Auth: {tok}' http://{host}/deploy",
        [("tok", "CREDENTIAL"), ("host", "INTERNAL_URL")],
    ),
    (
        "ssh-keyscan {host} > known_hosts",
        [("host", "INTERNAL_URL")],
    ),

    # 26. Email + name in incident notes.
    (
        "Reporter {name} <{email}> opened incident on {host}",
        [("name", "PII_NAME"), ("email", "PII_EMAIL"), ("host", "INTERNAL_URL")],
    ),
    (
        "cc: {email} (Slack: @{name})",
        [("email", "PII_EMAIL"), ("name", "PII_NAME")],
    ),

    # 27. SQL / database trace.
    (
        "SELECT id, name FROM users WHERE email = '{email}' LIMIT 1",
        [("email", "PII_EMAIL")],
    ),
    (
        "ERROR: connection to host \"{host}\" port 5432 failed: password authentication failed for user \"{name}\"",
        [("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),

    # 28. Stack trace / exception lines (where hostnames sneak into messages).
    (
        "ConnectionError: Could not resolve host {host} (attempt 3/3)",
        [("host", "INTERNAL_URL")],
    ),
    (
        "  at HttpClient.send (http://{host}/static/app.js:1024:18)",
        [("host", "INTERNAL_URL")],
    ),

    # 29. INTERNAL_IP in dense log lines.
    (
        "{ip} - - [03/Apr/2025:10:14:22 +0900] \"GET /healthz\" 200 12",
        [("ip", "INTERNAL_IP")],
    ),
    (
        "denied: src={ip} dst={host} reason=acl",
        [("ip", "INTERNAL_IP"), ("host", "INTERNAL_URL")],
    ),
    (
        "kube_pod_info{{pod=\"cart-{rid}\", host_ip=\"{ip}\"}} 1",
        [("rid", "USER_ID"), ("ip", "INTERNAL_IP")],
    ),

    # 30. URL with path id buried mid-line.
    (
        "redirected to /api/users/{rid} after login by {name}",
        [("rid", "USER_ID"), ("name", "PII_NAME")],
    ),
    (
        "GET /v2/orders/{rid}/items returned 500",
        [("rid", "USER_ID")],
    ),

    # 31. Tokens in code reviews / GitHub-style snippets (not the secret hint
    # words, just plausible-looking variable names).
    (
        "let auth = `{tok}`; // TODO rotate",
        [("tok", "CREDENTIAL")],
    ),
    (
        "secrets.{name_upper} = '{opq}'  // do not commit",
        [("name_upper", "PII_NAME"), ("opq", "CREDENTIAL")],
    ),

    # 32. PII / CREDENTIAL in CSV-ish dumps.
    (
        "{rid},{name},{email},{ip}",
        [("rid", "USER_ID"), ("name", "PII_NAME"), ("email", "PII_EMAIL"), ("ip", "INTERNAL_IP")],
    ),
    (
        "user_id,host,token\n{rid},{host},{tok}",
        [("rid", "USER_ID"), ("host", "INTERNAL_URL"), ("tok", "CREDENTIAL")],
    ),

    # 33. Multi-line incident report with multiple categories.
    (
        "Incident summary:\n- target: {host}\n- analyst: {name} <{email}>\n- request id: {rid}\n- token used: {tok}",
        [("host", "INTERNAL_URL"), ("name", "PII_NAME"), ("email", "PII_EMAIL"),
         ("rid", "USER_ID"), ("tok", "CREDENTIAL")],
    ),

    # 34. Slack / chat-shaped messages (handles get caught separately by
    # rule, but in-prose names + hosts still need FT coverage).
    (
        "@{name} fyi {host} is throwing 500s for user {rid}",
        [("name", "PII_NAME"), ("host", "INTERNAL_URL"), ("rid", "USER_ID")],
    ),
    (
        "DM from {name}: \"can you rotate {tok}? leaked in jira\"",
        [("name", "PII_NAME"), ("tok", "CREDENTIAL")],
    ),

    # 35. Email body / ticket text.
    (
        "Hi {name},\n  We've revoked the API key {tok} that you reported.\n  - SecOps",
        [("name", "PII_NAME"), ("tok", "CREDENTIAL")],
    ),

    # 36. Curl / wget command lines with auth header (very common in HARs).
    (
        "curl -X POST -H \"Authorization: Bearer {tok}\" http://{host}/api/v1/orders -d '{{\"id\":{rid}}}'",
        [("tok", "CREDENTIAL"), ("host", "INTERNAL_URL"), ("rid", "USER_ID")],
    ),
    (
        "wget --header='X-API-Key: {opq}' http://{host}/export.csv",
        [("opq", "CREDENTIAL"), ("host", "INTERNAL_URL")],
    ),

    # 37. Kafka / message-broker traces.
    (
        "topic=user.events partition=3 offset={rid} key={email}",
        [("rid", "USER_ID"), ("email", "PII_EMAIL")],
    ),

    # 38. Container / k8s logs.
    (
        "[pod/cart-{rid}] connecting to {host}:5432 with user {name}",
        [("rid", "USER_ID"), ("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),

    # 39. INTERNAL_URL in plain prose without context words.
    (
        "after the migration, {host} stopped emitting metrics",
        [("host", "INTERNAL_URL")],
    ),
    (
        "{host} is the canonical source of truth for the warehouse data",
        [("host", "INTERNAL_URL")],
    ),

    # 40. Long token assignment in TOML / config.
    (
        "[auth]\nclient_secret = \"{opq}\"\nendpoint = \"http://{host}/oauth\"",
        [("opq", "CREDENTIAL"), ("host", "INTERNAL_URL")],
    ),

    # 41. HTML comments with author / copyright (typical SPA bundle leakage).
    (
        "<!-- Copyright (c) 2014-2026 {name} & the {host} contributors. -->",
        [("name", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),
    (
        "<!-- Built by {name_ja} for {host}. Do not modify. -->",
        [("name_ja", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),
    (
        "<title>{host}</title>\n  <meta name=\"author\" content=\"{name}\">",
        [("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),
    (
        "// (c) {name} <{email}> -- internal SDK do not redistribute",
        [("name", "PII_NAME"), ("email", "PII_EMAIL")],
    ),

    # 42. Author / contributor strings in CSS/JS bundles.
    (
        "/*! {host} v3.2 | (c) {name} | MIT */",
        [("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),
    (
        "/* @license {host} -- maintained by {name} */",
        [("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),

    # 43. Internal-but-public-looking domain (the juice-sh.op shape: a brand
    # domain on .op / .io / .dev that still wants to be masked because it
    # ties the trace to a specific organisation).
    (
        "Set-Cookie: session_id={opq}; Domain=.{host}; Path=/",
        [("opq", "CREDENTIAL"), ("host", "INTERNAL_URL")],
    ),
    (
        "Reported by {name} on {host} (admin@{host})",
        [("name", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),
    (
        "fetched manifest from https://{host}/manifest.webmanifest",
        [("host", "INTERNAL_URL")],
    ),
    (
        "<meta property=\"og:site_name\" content=\"{host}\">",
        [("host", "INTERNAL_URL")],
    ),

    # 44. Short opaque session-style ids (like Socket.IO sids,
    # `Yp_crOiZaE3qykxGAAAE` -- 20 chars, base64-ish).
    (
        "Set-Cookie: io={opq}; Path=/socket.io",
        [("opq", "CREDENTIAL")],
    ),
    (
        "wss://{host}/socket.io/?EIO=4&transport=websocket&sid={opq}",
        [("host", "INTERNAL_URL"), ("opq", "CREDENTIAL")],
    ),
    (
        "session sid: {opq} (issued to {name})",
        [("opq", "CREDENTIAL"), ("name", "PII_NAME")],
    ),

    # 45. Names embedded in URL paths or breadcrumbs (the "owner" pattern).
    (
        "/profile/{name}",
        [("name", "PII_NAME")],
    ),
    (
        "Welcome back, {name}! Your last login was from {ip}.",
        [("name", "PII_NAME"), ("ip", "INTERNAL_IP")],
    ),
    (
        "Hi {name}, your verification link expires in 10 minutes.",
        [("name", "PII_NAME")],
    ),

    # 46. PII_NAME inside JSON keys / values that aren't immediately obvious.
    (
        '{{"author":"{name}","commit":"{rid}","host":"{host}"}}',
        [("name", "PII_NAME"), ("rid", "USER_ID"), ("host", "INTERNAL_URL")],
    ),
    (
        '{{"reported_by":"{name}","email":"{email}"}}',
        [("name", "PII_NAME"), ("email", "PII_EMAIL")],
    ),
    (
        '"creator":{{"name":"{name}","email":"{email}"}}',
        [("name", "PII_NAME"), ("email", "PII_EMAIL")],
    ),

    # 47. PII_NAME embedded in long product/article description prose (the
    # `"description":"...by Uncle Dittmeyer."` shape).
    (
        '"description":"Made from oranges hand-picked by {name}."',
        [("name", "PII_NAME")],
    ),
    (
        '"description":"Reviewed by {name} on the staging cluster."',
        [("name", "PII_NAME")],
    ),
    (
        '"summary":"Issue raised by {name} after the deploy of {host}."',
        [("name", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),
    (
        '"note":"Acknowledged by {name_ja} (担当: {name})."',
        [("name_ja", "PII_NAME"), ("name", "PII_NAME")],
    ),
    (
        '"changelog":"Refactor by {name} -- removed dead code path"',
        [("name", "PII_NAME")],
    ),
    (
        '"footer":"Maintained by {name} since 2014. (c) {host}"',
        [("name", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),

    # 48. JSON application/config blocks with domain + project name pair
    # (the `"application":{"domain":"juice-sh.op","name":"..."}` shape).
    (
        '"application":{{"domain":"{host}","name":"{host}"}}',
        [("host", "INTERNAL_URL")],
    ),
    (
        '"site":{{"domain":"{host}","contact":"{email}"}}',
        [("host", "INTERNAL_URL"), ("email", "PII_EMAIL")],
    ),
    (
        '"project":{{"name":"{host}","owner":"{name}"}}',
        [("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),
    (
        '"meta":{{"domain":"{host}","author":"{name}","contact":"{email}"}}',
        [("host", "INTERNAL_URL"), ("name", "PII_NAME"), ("email", "PII_EMAIL")],
    ),
    (
        '"app":{{"name":"{host}","build":"{rid}","author":"{name}"}}',
        [("host", "INTERNAL_URL"), ("rid", "USER_ID"), ("name", "PII_NAME")],
    ),

    # 49. Multi-line HTML comment with year range + author (JuiceShop-shaped).
    (
        "<!--\n  ~ Copyright (c) 2014-2026 {name} & the {host} contributors.\n  ~ SPDX-License-Identifier: MIT\n  -->",
        [("name", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),
    (
        "<!--\n  Maintained by {name} <{email}>\n  Internal use only -- {host}\n  -->",
        [("name", "PII_NAME"), ("email", "PII_EMAIL"), ("host", "INTERNAL_URL")],
    ),
    (
        "/*!\n * {host} core library v3.2\n * (c) {name}\n * Released under MIT\n */",
        [("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),

    # 50. JSON catalog / product entries with name in nested fields.
    (
        '{{"id":{rid},"name":"{host} flagship","description":"By {name}, since 2014"}}',
        [("rid", "USER_ID"), ("host", "INTERNAL_URL"), ("name", "PII_NAME")],
    ),
    (
        '{{"items":[{{"name":"signed by {name}","price":1480}}]}}',
        [("name", "PII_NAME")],
    ),

    # 51. Domain in arbitrary JSON keys (the model needs to learn that any
    # value that *looks* like a brand domain (non-public TLD or single-word
    # brand on .op / .io / .dev / .ai) belongs to INTERNAL_URL).
    (
        '"hosts":["{host}","{host}"]',
        [("host", "INTERNAL_URL")],
    ),
    (
        '"links":{{"home":"https://{host}/","about":"https://{host}/about"}}',
        [("host", "INTERNAL_URL")],
    ),
]


# JSON-shaped templates kept in a separate list so we can dial the ratio.
# These are the patterns that surfaced as leaks in the Sample HAR demo and
# in JS bundle response bodies: numeric ID values under id-typed keys, plus
# the email/ip variants used together in user-detail responses.
_JSON_TEMPLATES: list = [
    # --- flat JSON: ids alone ---
    ('{{"id": {rid}, "status": "ok"}}', [("rid", "USER_ID")]),
    ('{{"id": {rid}, "name": "{name}"}}', [("rid", "USER_ID"), ("name", "PII_NAME")]),
    ('{{"user_id": {rid}, "role": "admin"}}', [("rid", "USER_ID")]),
    ('{{"basket_id": {rid}, "items": []}}', [("rid", "USER_ID")]),
    ('{{"order_id": {rid}, "qty": 3, "price": 1480}}', [("rid", "USER_ID")]),
    ('{{"product_id": {rid}, "qty": 1}}', [("rid", "USER_ID")]),

    # --- flat JSON: ids + email + ip / host ---
    (
        '{{"id": {rid}, "reporter": "{email}", "ip": "{ip}"}}',
        [("rid", "USER_ID"), ("email", "PII_EMAIL"), ("ip", "INTERNAL_IP")],
    ),
    (
        '{{"user_id": {rid}, "email": "{email}", "host": "{host}"}}',
        [("rid", "USER_ID"), ("email", "PII_EMAIL"), ("host", "INTERNAL_URL")],
    ),
    (
        '{{"id": {rid}, "owner": "{name}", "host": "{host}"}}',
        [("rid", "USER_ID"), ("name", "PII_NAME"), ("host", "INTERNAL_URL")],
    ),

    # --- flat JSON: tokens / credentials ---
    ('{{"token": "{tok}", "expires_in": 3600}}', [("tok", "CREDENTIAL")]),
    ('{{"api_key": "{opq}", "scope": "read:metrics"}}', [("opq", "CREDENTIAL")]),
    ('{{"access_token": "{tok}", "refresh_token": "{opq}"}}', [("tok", "CREDENTIAL"), ("opq", "CREDENTIAL")]),
    ('{{"client_secret": "{opq}", "client_id": "ID-{rid}"}}', [("opq", "CREDENTIAL"), ("rid", "USER_ID")]),

    # --- negative-discrimination: number-shaped non-ids ---
    (
        '{{"id": {rid}, "page": 1, "per_page": 50, "total": 4821}}',
        [("rid", "USER_ID")],
    ),
    (
        '{{"id": {rid}, "size": 2048, "duration_ms": 312, "retries": 0}}',
        [("rid", "USER_ID")],
    ),
    (
        '{{"order_id": {rid}, "items": [{{"sku":"SKU-A1","qty":3}},{{"sku":"SKU-B2","qty":1}}]}}',
        [("rid", "USER_ID")],
    ),

    # --- nested JSON: HAR response shapes (the Juice Shop body shape) ---
    (
        '{{"status":"success","data":{{"id":{rid},"username":"","email":"{email}","role":"admin","createdAt":"2026-04-20T13:01:18.439Z"}}}}',
        [("rid", "USER_ID"), ("email", "PII_EMAIL")],
    ),
    (
        '{{"status":"success","data":{{"id":{rid},"username":"{name}","email":"{email}","role":"customer"}}}}',
        [("rid", "USER_ID"), ("name", "PII_NAME"), ("email", "PII_EMAIL")],
    ),
    (
        '{{"data":{{"users":[{{"id":{rid},"email":"{email}"}}]}}}}',
        [("rid", "USER_ID"), ("email", "PII_EMAIL")],
    ),
    (
        '{{"meta":{{"request_id":"req-{rid}"}},"data":{{"host":"{host}","token":"{tok}"}}}}',
        [("rid", "USER_ID"), ("host", "INTERNAL_URL"), ("tok", "CREDENTIAL")],
    ),

    # --- arrays of records (typical pagination payload) ---
    (
        '{{"users":[{{"id":{rid},"email":"{email}"}},{{"id":{rid2},"email":"{email2}"}}]}}',
        [("rid", "USER_ID"), ("email", "PII_EMAIL"), ("rid2", "USER_ID"), ("email2", "PII_EMAIL")],
    ),
    (
        '[{{"id":{rid},"name":"{name}"}},{{"id":{rid2},"name":"{name2}"}}]',
        [("rid", "USER_ID"), ("name", "PII_NAME"), ("rid2", "USER_ID"), ("name2", "PII_NAME")],
    ),

    # --- HTTP request snippets that often live inside HAR strings ---
    (
        'GET http://{host}/api/users/{rid}\\nAuthorization: Bearer {tok}',
        [("host", "INTERNAL_URL"), ("rid", "USER_ID"), ("tok", "CREDENTIAL")],
    ),
    (
        'POST http://{host}/api/login\\n  body: {{"email":"{email}","password":"{opq}"}}',
        [("host", "INTERNAL_URL"), ("email", "PII_EMAIL"), ("opq", "CREDENTIAL")],
    ),
    (
        'GET http://{host}/api/Users/{rid}\\n  resp: {{"id":{rid},"email":"{email}","role":"admin"}}',
        [("host", "INTERNAL_URL"), ("rid", "USER_ID"), ("email", "PII_EMAIL")],
    ),

    # --- HAR-escaped JSON inside a string field (the shape that leaked
    # the {"id": 1001} value, where outer JSON quotes it as \"id\": 1001) ---
    (
        '"text": "{{\\"id\\": {rid}, \\"reporter\\": \\"{email}\\", \\"ip\\": \\"{ip}\\"}}"',
        [("rid", "USER_ID"), ("email", "PII_EMAIL"), ("ip", "INTERNAL_IP")],
    ),
    (
        '"content": {{"text": "{{\\"user_id\\": {rid}, \\"email\\": \\"{email}\\"}}"}}',
        [("rid", "USER_ID"), ("email", "PII_EMAIL")],
    ),

    # --- key-value config dumps (.env-as-JSON, helm values, etc.) ---
    (
        '{{"DATABASE_URL":"postgres://{name}:{tok}@{host}:5432/db","REDIS_HOST":"{host}"}}',
        [("name", "PII_NAME"), ("tok", "CREDENTIAL"), ("host", "INTERNAL_URL")],
    ),
    (
        '{{"smtp":{{"host":"{host}","user":"{email}","password":"{opq}"}}}}',
        [("host", "INTERNAL_URL"), ("email", "PII_EMAIL"), ("opq", "CREDENTIAL")],
    ),

    # --- arrays of ids (IDOR enumeration shape) ---
    (
        '{{"member_ids": [{rid}, {rid2}, {rid3}]}}',
        [("rid", "USER_ID"), ("rid2", "USER_ID"), ("rid3", "USER_ID")],
    ),

    # --- mixed dump with everything (stress test) ---
    (
        '{{"id":{rid},"owner":{{"name":"{name}","email":"{email}"}},"endpoint":"http://{host}","creds":{{"api_key":"{opq}","token":"{tok}"}}}}',
        [("rid", "USER_ID"), ("name", "PII_NAME"), ("email", "PII_EMAIL"),
         ("host", "INTERNAL_URL"), ("opq", "CREDENTIAL"), ("tok", "CREDENTIAL")],
    ),
]


def _add_span(spans: list[dict], text: str, value: str, category: str) -> None:
    idx = text.find(value)
    if idx < 0:
        return
    spans.append({"start": idx, "end": idx + len(value), "value": value, "category": category})


def _sample(template: tuple) -> Sample:
    tpl, slots = template
    name_en = _gen_person_name_en()
    name_en2 = _gen_person_name_en()
    while name_en2 == name_en:
        name_en2 = _gen_person_name_en()
    values = {
        "tok": _gen_custom_token(),
        "opq": _gen_opaque_cred(),
        "host": _gen_bare_internal_host(),
        "ip": _gen_inline_ip_no_context(),
        "rid": _gen_resource_id(),
        "rid2": _gen_resource_id(),
        "rid3": _gen_resource_id(),
        "name": name_en,
        "name2": name_en2,
        # Upper-case form used as a constant identifier ("ALICE" etc).
        "name_upper": name_en.split()[0].upper(),
        "name_ja": _gen_person_name_ja(),
        "email": _gen_email(),
        "email2": _gen_email(),
        "port": str(random.choice([80, 443, 5432, 6379, 8080, 9092, 27017])),
    }
    text = tpl.format(**values)

    spans: list[dict] = []
    for slot_key, category in slots:
        # Skip helper slots that are only there for formatting (e.g. port
        # numbers) and aren't a category we mask.
        if category == "INTERNAL_URL_PORT_IGNORE":
            continue
        _add_span(spans, text, values[slot_key], category)
    return Sample(input=text, spans=spans)


def generate(n: int, seed: int = 42, json_ratio: float = 0.3) -> list[Sample]:
    """Generate n samples. ``json_ratio`` controls the share of JSON-shaped
    templates so we can keep that distribution stable regardless of how many
    other templates exist."""
    random.seed(seed)
    out: list[Sample] = []
    for i in range(n):
        if random.random() < json_ratio:
            tpl = random.choice(_JSON_TEMPLATES)
        else:
            tpl = random.choice(_TEMPLATES)
        out.append(_sample(tpl))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--n", type=int, default=800)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--split", type=float, default=0.1, help="Validation split ratio (0.0 - 0.5).")
    args = ap.parse_args()

    samples = generate(args.n, seed=args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    n_val = int(len(samples) * args.split)
    train, val = samples[n_val:], samples[:n_val]

    def _write(path: Path, items: list[Sample]) -> None:
        with path.open("w", encoding="utf-8") as f:
            for s in items:
                f.write(json.dumps({"input": s.input, "spans": s.spans}, ensure_ascii=False) + "\n")

    _write(args.out, train)
    if n_val > 0:
        val_path = args.out.with_name(args.out.stem + ".val" + args.out.suffix)
        _write(val_path, val)
        print(f"wrote train={len(train)} to {args.out}")
        print(f"wrote val={len(val)} to {val_path}")
    else:
        print(f"wrote {len(train)} samples to {args.out}")


if __name__ == "__main__":
    main()
