# a2a-trust-audit

Score any A2A agent card on identity, authentication, authorization, and behavioral trust. Zero install. One npx away.

[![npm version](https://img.shields.io/npm/v/@agentlair/a2a-trust-audit.svg)](https://www.npmjs.com/package/@agentlair/a2a-trust-audit)
[![license](https://img.shields.io/npm/l/@agentlair/a2a-trust-audit.svg)](LICENSE)
[![A2A Trust](https://agentlair.dev/badge/a2a/aHR0cHM6Ly9hZ2VudGxhaXIuZGV2Ly53ZWxsLWtub3duL2FnZW50Lmpzb24)](https://agentlair.dev/blog/a2a-trust-leaderboard-may-2026/)

## Get a badge

Embed a live trust grade in your README:

```md
![A2A Trust](https://agentlair.dev/badge/a2a/<base64url-of-card-url>)
```

Encode your card URL:

```bash
echo -n 'https://your-agent.example.com/.well-known/agent.json' | base64 | tr -d '=' | tr '/+' '_-'
```

Paste the output into the badge URL. It re-audits hourly — your grade stays current without any CI.

## Why

The A2A protocol tells agents how to talk. It doesn't tell them how to trust.

Most agent cards score 0% on behavioral trust (L4). The spec has no standard for it. This tool makes that gap visible, layer by layer, in 10 seconds.

## Run it

```bash
npx @agentlair/a2a-trust-audit https://your-agent.example.com
```

That's the install. There isn't one.

```bash
# Audit a local card file
npx @agentlair/a2a-trust-audit ./agent-card.json

# Compare multiple agents
npx @agentlair/a2a-trust-audit https://agent-a.com https://agent-b.com

# JSON output (pipe to jq, feed to CI)
npx @agentlair/a2a-trust-audit https://your-agent.example.com --json

# Skip the live endpoint probe (faster, less signal)
npx @agentlair/a2a-trust-audit https://your-agent.example.com --no-probe
```

## CI/CD

Run the audit on every PR with the GitHub Action: [`piiiico/a2a-trust-audit-action`](https://github.com/piiiico/a2a-trust-audit-action).

```yaml
# .github/workflows/a2a-audit.yml
- uses: piiiico/a2a-trust-audit-action@v1
  with:
    card-url: https://your-agent.example.com
    fail-below: B
```

It posts the score breakdown as a PR comment, writes the report to the job summary, exposes `grade` / `score` / `l1`–`l4` outputs, and fails the run if the grade drops below your threshold. The action vendors the audit logic from this package, so the rubric matches exactly.

## What it checks

20+ properties across four layers, weighted by severity:

| Layer | Covers | Typical score |
|-------|--------|---------------|
| L1 Identity | Name, DID, provider, contact, HTTPS, schema | 60-100% |
| L2 Authentication | OAuth, JWKS, card signature, x402, mTLS | 20-90% |
| L3 Authorization | Skills, capabilities, I/O modes | 80-100% |
| L4 Behavioral Trust | Trust attestation, audit trail, monitoring | 0-90% |

## The 401 vs 402 probe

If you give it a URL, the audit probes one of the agent's skill endpoints with an unauthenticated POST. The status code is a different signal from the card.

- **402 Payment Required.** x402 detected. The caller commits before the agent acts. Skin in the game on both sides.
- **X-402-Version response header.** x402 middleware is wired even if the current request hit auth first.
- **401 Unauthorized.** Auth gap. Standard, table-stakes.
- **200 OK.** Open endpoint. Easy to spam.

x402 scores high because payment-gating is the only auth mechanism that makes the *caller* prove commitment. Bearer tokens and OAuth prove only that the operator gates access. Different question.

## Scoring

Each check has a severity (critical/high/medium/low) that determines its weight. Layer scores roll into an overall grade:

- L1 Identity: 20%
- L2 Authentication: 30%
- L3 Authorization: 15%
- L4 Behavioral Trust: 35%

Behavioral trust is weighted highest because it closes the TOCTOU gap between verification at check time and behavior at use time. The other layers can't.

Grades: A (90+), B (80+), C (65+), D (50+), F (<50).

## Sample output

Run against agentlair.dev:

```
A2A Trust Audit
─────────────────────────────────────────────
Target: https://agentlair.dev
Agent: AgentLair v0.18.3
Probe: 401 x402

Scores
  L1 Identity            ██████████████████████████████  100%
  L2 Authentication      ██████████████████████████░░░░  88%
  L3 Authorization       ██████████████████████████████  100%
  L4 Behavioral Trust    ██████████████████████████░░░░  87%
  ─────────────────────────────────────────────
  OVERALL                ████████████████████████████░░  92%
  Grade: A
```

Run against an unsigned card with no DID, no JWKS, no trust attestation:

```
Scores
  L1 Identity            ██████████████████████░░░░░░░░  73%
  L2 Authentication      ██████████░░░░░░░░░░░░░░░░░░░░  33%
  L3 Authorization       ██████████████████████████████  100%
  L4 Behavioral Trust    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0%
  OVERALL                ████████████░░░░░░░░░░░░░░░░░░  43%
  Grade: F

Verdict: This agent card has no behavioral trust layer.
```

## Extending your card

The tool checks for fields that aren't in the A2A spec but don't conflict with it:

```json
{
  "did": "did:web:your-agent.example.com",
  "jwks_uri": "https://your-agent.example.com/.well-known/jwks.json",
  "trust_attestation": {
    "score": 78,
    "level": "junior",
    "confidence": 0.85,
    "computed_at": "2026-05-09T22:00:00Z"
  },
  "audit_trail_url_template": "https://your-agent.example.com/v1/audit/{jti}",
  "behavioral_monitoring": {
    "provider": "agentlair.dev",
    "type": "continuous"
  },
  "card_signature": "eyJhbGciOiJFZERTQSI..."
}
```

None of these require changes to the A2A protocol. Any agent can adopt them.

`audit_trail_url_template` uses RFC 6570 URI templates with `{jti}` as the JWT ID placeholder. Per-transaction audit beats a global feed.

## Why the L4 gap matters

A signed JWT proves who the agent claims to be at issue time. It tells you nothing about what that agent has done since. Identity without behavioral attestation is a postcard with no postmark.

This tool exists because someone has to make the gap legible before anyone fixes it.

## In the wild

We pointed the tool at every public A2A agent card we could find. 18 cards. 17 graded F. Averages across the 17 non-AgentLair agents:

| Layer | Average | What's missing |
|-------|--------:|----------------|
| L1 Identity | 80.1 | DIDs are absent everywhere; two cards omit a provider block |
| L2 Authentication | 13.1 | Zero signed cards, zero JWKS, two declare x402 |
| L3 Authorization | 100.0 | Skills and capabilities are well-declared across the ecosystem |
| L4 Behavioral Trust | 0.0 | No trust attestation, no audit trail, no monitoring endpoint |

L3 is solved. L1 is mostly solved. L2 is the systemic gap. L4 is empty.

Full leaderboard with per-agent scores: [A2A Trust Leaderboard, May 2026](https://agentlair.dev/blog/a2a-trust-leaderboard-may-2026/).

## Reference implementation

[AgentLair](https://agentlair.dev) is the L4 reference implementation. It scores A (92%) on its own card. The tool was written against it. If you build a competing implementation that scores higher, file an issue. That's the point.

For the longer argument, see [Your Agent Card is Naked](https://agentlair.dev/blog/your-agent-card-is-naked/).

## License

MIT
