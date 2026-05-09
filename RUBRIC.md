# a2a-trust-audit — Rubric

Authoritative source for every check in `src/audit.ts`. Re-derived 2026-05-09 against canonical specs.

## Spec landscape

The audit grades agent cards on a **superset** of the canonical A2A schema, because A2A v1.0 has **no L4 (behavioral trust) layer** and only a partial L2. The L4 / extension fields below (`trust_attestation`, `audit_trail_url_template`, `did`, `jwks_uri`, `card_signature`) are reasonable de-facto extensions that show up in real-world cards (AgentLair's reference impl). They are **labelled as extensions in the rubric** so callers know what's spec vs. what's our opinion.

### Primary sources
- **A2A v1.0** — `specification/a2a.proto` in [a2aproject/A2A](https://github.com/a2aproject/A2A); JSON shape per proto3 JSON mapping (camelCase). Spec doc: <https://a2a-protocol.org/latest/specification/>.
- **A2A v0.3+ migration** — well-known path `/.well-known/agent-card.json` (IANA-registered 2025-08-01, change controller Linux Foundation, RFC 8615). Legacy `/.well-known/agent.json` accepted for back-compat (v0.2.5 and earlier).
- **RFC 7517** — JWKS (`jwks_uri` is a JOSE/RFC 7517 convention; not in A2A core).
- **RFC 6570** — URI Templates (`audit_trail_url_template`, `trust_endpoint_template`).
- **RFC 6750** — Bearer tokens.
- **RFC 8414 / RFC 9728** — OAuth metadata (informs OAuth `type` discrimination in `securitySchemes`).
- **W3C DID Core** — `did:` prefix conventions.
- **x402 spec** — <https://github.com/coinbase/x402>; 402 + `accepts: PaymentRequirements[]` + headers `X-402-Version`, `X-Payment-Response`, `X-Payment-Required`.
- **AgentLair reference card** — `https://agentlair.dev/.well-known/agent.json` (canonical L4 implementation).
- **IETF agent-identity drafts** — see `memory/knowledge/ietf-agent-identity-landscape-2026-05.md`. Behavioral trust is an open gap; AAT and receipt chains are NOT differentiated.

### Drift findings (2026-05-09 review)

- **A2A v1.0 has no `schema_version` field.** Spec uses `version` (agent self-version) and `protocolVersion` on `AgentInterface`. The "0.8" seen in AgentLair's card is non-canonical. **Subtraction:** remove `l1-schema`.
- **A2A v1.0 prefers `securitySchemes` over `authentication.schemes`.** v1.0 uses `securitySchemes: map<string, SecurityScheme>` + `securityRequirements`. The legacy nested `authentication.schemes` array is v0.2.x/v0.3 era. Audit must accept both shapes.
- **Card signing field migrated from `card_signature` to `signatures: AgentCardSignature[]`** in v1.0. Audit must accept both.
- **`l2-oauth`'s fallback `|| !!card.security_schemes` is too generous** — it claims OAuth support whenever any `securitySchemes` object exists, even bearer-only. Must inspect entry types (`oauth2`, `openIdConnect`).
- **`l2-mtls` only inspects `authentication.schemes`** — must also check `securitySchemes` entries for type `mutualTLS`.
- **`l3-skill-ids` only verifies `id`.** v1.0 marks `id`, `name`, `description`, `tags` as REQUIRED on every `AgentSkill`. Sharpen to verify all four (no new check id; existing check tightened).
- **`l1-url` is severity `high`** but A2A v1.0 marks `url` as REQUIRED → critical.
- **`l1-version` is severity `low`** but A2A v1.0 marks `version` as REQUIRED → medium.
- **`l1-contact` (`contact.email`/`contact.url`) is not in A2A v1.0** — useful for vulnerability disclosure but should be downgraded from `medium` → `low` since it's an extension, not canonical.

### Public-agent spot-check inventory

Search of `/workspace/agentlair/apps/web/src/content/blog/` for live `agent.json` URLs surfaced only `https://agentlair.dev/.well-known/agent.json`. The IETF landscape (`memory/knowledge/ietf-agent-identity-landscape-2026-05.md`) lists drafts but no second public live card we can curl. **Spot-check inventory accepted as one (agentlair.dev) + synthetic-card edge cases.**

---

## Atomic check rubric

| ID | Layer | Severity | Source | Status | Notes |
|---|---|---|---|---|---|
| **l1-name** | L1 | critical | A2A v1.0 — `AgentCard.name` REQUIRED | current | Sharp. |
| **l1-description** | L1 | high | A2A v1.0 — `AgentCard.description` REQUIRED | current | Sharp. |
| **l1-url** | L1 | high → **critical** | A2A v1.0 — `AgentCard.url` REQUIRED | **sharpened** | Severity raised to match REQUIRED status. |
| **l1-https** | L1 | critical | RFC 7230, transport baseline | current | A2A doesn't mandate but no production endpoint should ship plaintext. |
| **l1-version** | L1 | low → **medium** | A2A v1.0 — `AgentCard.version` REQUIRED | **sharpened** | Severity raised; pinning matters for consumers. |
| ~~l1-schema~~ | ~~L1~~ | ~~medium~~ | **NOT IN A2A v1.0** | **subtracted** | Field `schema_version` doesn't exist in canonical spec. AgentLair's "0.8" is non-canonical. |
| **l1-contact** | L1 | medium → **low** | AgentLair extension (no `contact` field in A2A v1.0) | **sharpened** | Useful for vulnerability disclosure; severity reduced to reflect non-canonical status. |
| **l1-provider** | L1 | medium | A2A v1.0 — `AgentProvider` requires `url`, `organization` | current | Sharp. |
| **l1-did** | L1 | high | W3C DID Core (extension to A2A) | current | Detection accepts any `did:` prefix anywhere in the card; reasonable for web/key/etc. |
| **l2-auth-declared** | L2 | critical | A2A v1.0 `securitySchemes` + legacy `authentication.schemes` | **sharpened** | Detail message now identifies whether legacy or v1.0 shape was found. |
| **l2-oauth** | L2 | medium | RFC 8414 / OpenAPI security scheme types | **sharpened** | Removed over-eager `\|\| !!card.security_schemes`; now inspects entry types for `oauth2` / `openIdConnect`. |
| **l2-jwks** | L2 | high | RFC 7517 (extension to A2A — A2A uses inline `signatures.header.jwk`) | current | Accepts `jwks_uri`, `jwks_url`, `jwksUri`. |
| **l2-card-signed** | L2 | critical | A2A v1.0 `signatures: AgentCardSignature[]` + legacy `card_signature` (JWS) | **sharpened** | Now accepts both shapes. |
| **l2-x402** | L2 | high | x402 spec + probe (401+headers / 402 status) | current | Probe-based detection is sharp. Field detection accepts `x402`, `accepts`, `payment_schemes`, `payment_required`, `pricing`. |
| **l2-mtls** | L2 | low | TLS 1.3 mTLS (RFC 8446 §4.2.4) | **sharpened** | Now inspects both `authentication.schemes` and `securitySchemes` for type `mutualTLS`. |
| **l3-skills** | L3 | high | A2A v1.0 — `AgentCard.skills` REQUIRED, ≥1 | current | Sharp. |
| **l3-skill-ids** | L3 | medium | A2A v1.0 — `AgentSkill.id`/`name`/`description`/`tags` REQUIRED | **sharpened** | Same id; now verifies all four required fields per skill, not just `id`. |
| **l3-io-modes** | L3 | medium | A2A v1.0 — `defaultInputModes` / `defaultOutputModes` REQUIRED | current | Sharp. |
| **l3-capabilities** | L3 | medium | A2A v1.0 — `AgentCapabilities` (fixed shape: `streaming`, `pushNotifications`, `extensions`, `extendedAgentCard`) | current | Loose check accepted for back-compat with cards using legacy keys (e.g. AgentLair's `stateTransitionHistory`). |
| **l4-trust-attestation** | L4 | critical | AgentLair extension (no L4 in A2A v1.0; closest = `draft-aamdal-rats-eat-behavioral-00` future I-D) | current | Accepts `score` (numeric trust), `level`, `confidence`, OR `trust_endpoint_template` (RFC 6570). |
| **l4-audit-trail** | L4 | high | AgentLair extension (closest = SCITT WG receipts) | current | Accepts both static `audit_trail_url` and template `audit_trail_url_template` (RFC 6570). Hot-fixed 2026-05-09. |
| **l4-behavioral-ref** | L4 | high | AgentLair extension (closest = RATS EAT-AI behavioral profile) | current | Substring match on `behavioral`, `telemetry`, `monitoring` keys — intentionally loose. |
| **l4-delegation** | L4 | medium | AgentLair extension (closest = APS three-signature chain, AITLP delegation) | current | Substring match on `delegation`, `provenance`, `chain`. |

## Subtraction count

**1** — `l1-schema` removed entirely.

## Sharpening count

**8** — `l1-url` severity, `l1-version` severity, `l1-contact` severity, `l2-auth-declared` detail, `l2-oauth` detection, `l2-card-signed` detection, `l2-mtls` detection, `l3-skill-ids` required-field set.

## Out of scope

- Adding NEW checks (e.g. "skill examples present", "extendedAgentCard capability", "iconUrl reachable")
- Validating against A2A JSON Schema (would require pulling generated artifact at build time)
- CLI UX changes
- Multiple-interface (`additionalInterfaces`) handling

## Re-derive procedure

When the rubric next drifts, repeat:
1. Pull the latest `a2aproject/A2A` proto and changelog.
2. Pull the live AgentLair card (`https://agentlair.dev/.well-known/agent.json`) — it tends to lead the spec for L4.
3. For each row in this table, verify the source URL still resolves and the field name still exists.
4. Sharpen detection (accept both legacy + canonical) before raising severity.
5. Subtract before adding — delete checks for fields that left the spec.
