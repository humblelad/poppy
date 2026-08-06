# Poppy: A Local Secret Firewall for LLM Traffic

*Built for Claude Currently.*

Coding agents read your files. When Claude Code opens a `.env`, your production credentials go to a third-party API — not because anyone decided to send them, but because the agent needed context.

Poppy is a local proxy that swaps real secrets for structurally-valid fakes before the request leaves your machine, and swaps them back before you see the answer. Same workflow, same output, no credential ever leaves localhost.

Point your client at Poppy instead of the API directly. Everything else stays exactly the same: your API key, your request format, your response handling.

![Python 3.14](https://img.shields.io/badge/python-3.14-blue)
![FastAPI](https://img.shields.io/badge/framework-FastAPI-009688)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

## How it works

```
Client → Poppy → sanitize (real secret → fake secret) → api.anthropic.com
Client ← Poppy ← rehydrate (fake secret → real secret) ← api.anthropic.com
```

1. Poppy receives your request and scans the body for developer secrets using 100+ tuned regex patterns.
2. Any match is swapped for a structurally realistic fake (e.g. a real AWS key becomes a fake key that still starts with `AKIA`), and the mapping is stored in an in-memory vault.
3. The sanitized request, with your original auth headers untouched, is forwarded to `api.anthropic.com`.
4. Before the response reaches you, Poppy swaps the fake secrets back for the real ones, safely handling cases where a fake secret is split across multiple streamed SSE chunks.

## Why not just block the secret?

The obvious alternative is what most DLP tools do: detect a secret and either refuse the request or replace it with `<REDACTED>`. Both work, and both are why people turn those tools off.

**Blocking breaks the task.** The agent asked to read that file for a reason. A blocked request isn't a protected developer, it's a developer who disables the proxy and sends the file anyway. Security controls that impose a workflow tax get removed — the failure mode isn't a blocked leak, it's an uninstalled tool.

**Redaction breaks the model's reasoning.** `<REDACTED>` is not a neutral substitution. Replace `postgresql://user:hunter2@prod-db:5432/app` with a tag and you've destroyed the structure the model needed: it can no longer tell you the connection string is missing `?sslmode=require`, or that the host points at prod, or that the port is wrong. You didn't hide a secret from the model, you hid *the shape of your config* from the model, and the answer you get back is worse. Redaction tags also drift out of the model's output in unpredictable ways — it will happily invent text around a `<REDACTED>` marker or echo it back mangled, and there is no reliable way to undo that.

**Poppy substitutes instead of subtracting.** A real AWS key becomes a fake key that still starts with `AKIA` and still has 16 trailing characters. The model sees a well-formed credential in a well-formed file and reasons about it exactly as it would the real one. Then the vault reverses the mapping on the way back, so the answer you read contains your actual key. The model's context is complete, your output is correct, and the real value never left the process.

| | Block | `<REDACTED>` | Poppy |
|---|---|---|---|
| Request completes | ✗ | ✓ | ✓ |
| Model sees valid structure | — | ✗ | ✓ |
| Answer references real values | — | ✗ | ✓ |
| Secret reaches the API | ✗ | ✗ | ✗ |
| Survives user impatience | ✗ | partly | ✓ |

The last row is the one that matters. A control only protects you while it's switched on, and the way to keep it switched on is to make it invisible.

## Features

- **Transparent drop-in proxy**: no client code changes beyond the base URL; auth headers pass straight through.
- **100+ tuned secret-detection patterns**: AWS, GitHub, Stripe, GCP, Azure, Slack, Twilio, SendGrid, Shopify, Discord, Telegram, JWTs, and database connection strings (Postgres/MySQL/Mongo/Redis/AMQP), plus 90+ generic service key patterns.
- **Semantic camouflage**: secrets are replaced with structurally valid fakes rather than generic `<REDACTED>` tags, so the LLM still receives plausible-looking input.
- **Stateful vault with reverse mapping**: a 1:1 real↔fake mapping enables consistent redaction and reliable rehydration.
- **Streaming-safe rehydration**: a sliding-window buffer ensures fake secrets are never missed even when split across SSE chunks.
- **JSON-aware sanitization**: request bodies are decoded before scanning so word-boundary regexes work correctly, then re-encoded to preserve the original wire format.
- **Data-only rule config**: detection patterns and fake generators are declarative JSON, so a config file can't execute code in the process holding your secrets.
- **Dependency-light**: no ML/NLP dependencies in v1. Detection and fake generation are pure standard library (`re`, `secrets`); the only third-party packages are the web stack itself.

## Installation

Requires Python 3.14.

```bash
# Clone this repository, then from its root:

python -m venv venv

# Activate the virtual environment
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

pip install -r requirements.txt
```

## Usage

Start the proxy:

```bash
python main.py
```

This runs Poppy on `http://0.0.0.0:8000`.

Point any Claude client at Poppy by setting `ANTHROPIC_BASE_URL` to Poppy's address instead of the real API. Your real API key stays exactly as it is.

### Example 1: Claude Code `settings.json`

Add the base URL override to your Claude Code settings file (e.g. `.claude/settings.json`):

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8000"
  }
}
```

Every Claude Code session using that settings file now routes through Poppy automatically.

### Example 2: One-off terminal usage

Set the environment variable inline for a single command:

```bash
ANTHROPIC_BASE_URL=http://localhost:8000 claude --model haiku -p "Hello, my name is humblelad. whats my name."
```

Behind the scenes, Poppy scans every request for developer secrets (like AWS keys or tokens) before forwarding it upstream, and rehydrates the real values back into the response, including streamed output, so nothing changes from the client's point of view except the base URL.

### Worked example: an AWS key in `test.py`

Say `test.py` in your project contains a real AWS access key:

```python
string = "AKIAOA3G5IRWJCOB7VTK"
```

You open the Claude Code chat panel in the VS Code extension (pointed at Poppy via `ANTHROPIC_BASE_URL`, as above) and ask: *"what's in test.py?"*

1. Claude Code reads the file and sends its contents to the model as part of the request. The real key `AKIAOA3G5IRWJCOB7VTK` is now in the outbound JSON body.
2. Poppy intercepts the request and sanitizes the body before forwarding it.
3. The sanitizer decodes the JSON and scans every string value against its 100+ secret patterns. The `AWS_ACCESS_KEY_ID` pattern (`AKIA` + 16 alphanumeric characters) matches.
4. The matched key has no existing mapping yet, so Poppy generates a fake: it keeps the real `AKIA` prefix and replaces the rest with 16 random uppercase letters, e.g. `AKIAQXPLKMZTBNCVWFRS`. The real↔fake pair is stored in the vault.
5. The real key in the request body is swapped for the fake one, and the sanitized request, with your original auth headers untouched, is forwarded to `api.anthropic.com`. The model only ever sees the fake key.
6. When the response comes back, Poppy checks it for any fake secrets from the vault (handling this safely even if a streamed response splits the fake key across chunks) and swaps them back for the real ones.
7. You see Claude's answer referencing your real key, `AKIAOA3G5IRWJCOB7VTK`, even though it never actually reached the API's servers.

## Configuring detection rules

Everything Poppy detects lives in `security_config.json`. A rule is two entries: a **pattern** that says what to catch, and a **generator** that says what to send instead.

### Example: add a Groq API key

Poppy ships no rule for [Groq](https://groq.com), whose keys look like `gsk_` followed by 52 alphanumeric characters. So a key sitting bare in a scratch file or a curl command — no `api_key=` label next to it — goes upstream verbatim today:

```
curl -H "Authorization: Bearer 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" https://api.groq.com/openai/v1/models
```

**1.** Add the pattern under `secret_patterns`:

```json
"GROQ_API_KEY": "gsk_[a-zA-Z0-9]{52}"
```

**2.** Add a generator under `fake_generators`, named to match:

```json
"GROQ_API_KEY": {"type": "prefix_random", "prefix": "gsk_", "length": 52, "charset": "alnum"}
```

**3.** Restart the proxy — config is read once at startup.

Now the same request leaves your machine carrying `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` instead. Claude still sees a well-formed Groq key in a well-formed curl command, so it can still tell you the header is malformed or the endpoint is wrong — and Poppy restores the real key before the answer reaches you.

That's the whole workflow: one pattern, one generator, restart. Everything below is reference.

### Generator types

| `type` | Fields | Produces |
|---|---|---|
| `prefix_random` | `prefix`, `length`, `charset` | `prefix` + random filler, e.g. `gsk_…` |
| `random` | `length`, `charset` | A random string, no prefix |
| `literal` | `value` | The same fixed string, every time |
| `template` | `template` | Literal text with `{random:LEN:CHARSET}` / `{uuid}` placeholders, for multi-part values like JWTs and webhook URLs |
| `connection_string` | — | A URI keeping the real scheme (`postgresql`, `mongodb`, …), faking the rest |

`charset` defaults to `alnum`; also available are `alnum_lower`, `alnum_upper`, `alpha_lower`, `alpha_upper`, `hex`, `digits`, and `urlsafe`.

`prefix_random` also takes `preserve_prefix: N`, which carries the real value's first N characters over instead of the fixed prefix — that's how a `ghs_` token stays `ghs_` rather than becoming `ghp_`.

### Notes

**If your pattern matches surrounding text, tag the value.** Whatever the pattern matches is what gets replaced. `gsk_[a-zA-Z0-9]{52}` matches only the key, so that's fine. But a pattern that includes the field name would swallow it whole — wrap the value in `(?P<secret>…)` and only that part is swapped:

```json
"MYCO_TOKEN": "myco_token\\s*[:=]\\s*['\"]?(?P<secret>[a-zA-Z0-9]{32})['\"]?"
```

```
myco_token = "abcdefghij0123456789abcdefghij12"   ->   myco_token = "myco_5RMaTkYvIuMxyrSIuv0gDLAyFnl"
```

**Your rule always beats the built-in generic ones.** `GENERIC_API_KEY` and the `generic_services` rules are matched last, so they only fill gaps your own rules didn't cover.

**Naming.** The longest generator name contained in the rule name wins — `SLACK_WEBHOOK` beats `SLACK` for `SLACK_WEBHOOK_URL`.

**Mistakes fail safe.** A malformed generator is skipped with a warning and the secret still gets replaced, just with a plain random string.

**Config is data, never code.** It can only pick a type and pass it parameters. New *types* go in `GENERATOR_BUILDERS` in `security_engine.py`, where they're reviewed as code.

**`generic_services`** is a shortcut: add a service name, get a rule matching any `key`/`token`/`secret`/`password` field holding 16+ characters.

## Project structure

```
main.py               FastAPI app: reverse proxy, sanitize/forward/rehydrate pipeline
security_engine.py     Vault (real↔fake mapping) and SecurityEngine (regex scan + JSON-aware sanitize)
stream_buffer.py        StreamRehydrator: buffers SSE chunks for safe rehydration mid-stream
security_config.json    Secret patterns, per-service fake generators, and generic service list
requirements.txt        Python dependencies
```

## Architecture (v1)

Poppy v1 uses a minimal, native Python `re` (regex) based architecture.

```mermaid
flowchart TB
    Client(["<b>Client</b><br/>Claude Code, SDK, curl"])
    Route["<b>1.</b> Catch-all route <i>(main.py)</i><br/>strip host + content-length headers"]
    Decode["<b>2.</b> Decode JSON<br/>walk every string key and value"]
    Scan["<b>3.</b> Scan 100+ regex patterns<br/>tuned rules resolve before generic fallbacks"]
    Swap["<b>4.</b> Swap in fakes, re-encode JSON<br/>your auth headers pass through untouched"]
    API(["<b>api.anthropic.com</b><br/>sees only fake secrets"])
    Split{"<b>5.</b> Response<br/>content-type?"}
    Stream["<b>6a.</b> StreamRehydrator <i>(stream_buffer.py)</i><br/>sliding-window buffer, cut on newline<br/>survives a fake split across chunks"]
    Whole["<b>6b.</b> Read full body<br/>replace every fake with its real value"]
    Done(["<b>Client</b><br/>sees real secrets restored"])

    Vault[("<b>Vault</b><br/><i>security_engine.py</i><br/>real ↔ fake, 1:1<br/>process-global")]

    Client ==>|"request"| Route
    Route ==> Decode ==> Scan ==> Swap
    Swap ==>|"sanitized body"| API
    API ==> Split
    Split ==>|"text/event-stream"| Stream
    Split ==>|"anything else"| Whole
    Stream ==>|"rehydrated chunks"| Done
    Whole ==>|"rehydrated body"| Done

    Scan -.->|"store real,<br/>mint semantic fake"| Vault
    Vault -.->|"fake value"| Swap
    Vault -.->|"reverse lookup"| Stream
    Vault -.->|"reverse lookup"| Whole

    classDef endpoint fill:#eef2ff,stroke:#4f46e5,color:#1e1b4b
    classDef store fill:#fff7ed,stroke:#c2410c,color:#431407
    class Client,Done,API endpoint
    class Vault store
```

### How it works internally

1. **Pattern Matching:** It iterates over 100+ highly tuned regular expressions (`SECRET_PATTERNS`) to find developer secrets like AWS keys, Stripe tokens, GitHub PATs, and database connection strings.
2. **Overlap Resolution:** Tuned rules claim their span before broad fallbacks like `GENERIC_API_KEY`, so a specific rule is never shadowed by a generic one that starts earlier at a field name. Within each class, overlaps resolve earliest then longest. Patterns that must match surrounding context wrap the value in `(?P<secret>…)` so only the secret is swapped and `api_key="<fake>"` keeps its syntax.
3. **Semantic Camouflage:** Instead of replacing secrets with generic `<REDACTED>` tags, it generates structurally valid fake secrets (e.g., replacing a real AWS key with a fake key that still starts with `AKIA`).
4. **Stateful Tokenization:** It maintains a 1:1 mapping of real secrets to fake secrets, ensuring consistent redaction across multiple payloads and enabling reverse lookup.
5. **Data-Only Configuration:** Generators are built from declarative JSON specs rather than executable strings, so `security_config.json` stays pure data — it can be shared or accepted from others without granting code execution inside the process that holds the vault.

This native approach keeps the project dependency-light (detection and generation use only the standard library) and ensures maximum execution speed for regex-bound operations.

## Roadmap

v1 focuses on structured developer secrets via regex, which keeps it fast and dependency-light. v2 will add general PII/PHI detection (names, addresses, etc.) for broader DLP coverage. [Microsoft Presidio](https://microsoft.github.io/presidio/) is a candidate for this, since it can handle unstructured entity recognition that regex isn't suited for.

Poppy is built for Claude and forwards to `api.anthropic.com` only. The detection, vault, and stream-rehydration logic is provider-agnostic, so other providers are feasible, but nothing else has been tested, so support is Claude-only for now.


## License

MIT. *(No `LICENSE` file is committed yet. Add one at the repository root to make this official.)*
