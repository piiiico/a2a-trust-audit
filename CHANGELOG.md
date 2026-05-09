# Changelog

## v0.1.1 — 2026-05-09 — rubric re-derivation

The auditor's rubric was systematically re-derived from canonical sources
([A2A v1.0 proto](https://github.com/a2aproject/A2A), RFC 7517, RFC 6570,
W3C DID Core, x402 spec, AgentLair reference card). Subtraction over
addition: 1 check removed, 8 checks sharpened. No new checks.

See [RUBRIC.md](./RUBRIC.md) for the full per-check provenance table.

### Subtracted

- **`l1-schema`** — removed entirely. A2A v1.0 has no `schema_version` field.
  The "0.8" sometimes seen in cards (including AgentLair's) is non-canonical.
  v1.0 uses `version` (already checked) and `protocolVersion` on `AgentInterface`.

### Sharpened

- **`l1-url`** severity raised `high` → `critical` — A2A v1.0 marks `url` as REQUIRED.
- **`l1-version`** severity raised `low` → `medium` — A2A v1.0 marks `version` as REQUIRED.
- **`l1-contact`** severity reduced `medium` → `low` — `contact` is an
  AgentLair extension, not in A2A v1.0. Renamed for clarity.
- **`l2-auth-declared`** now identifies whether the legacy
  `authentication.schemes` array or the canonical v1.0 `securitySchemes` map
  was found, and shows the actual scheme names.
- **`l2-oauth`** detection fixed: removed the over-eager
  `|| !!card.security_schemes` fallback that claimed OAuth support whenever
  any `securitySchemes` object existed. Now inspects entry types for
  `oauth2` / `openIdConnect` per A2A v1.0 / OpenAPI security scheme types.
- **`l2-card-signed`** now accepts both `card_signature` (legacy single JWS)
  and `signatures: AgentCardSignature[]` (A2A v1.0).
- **`l2-mtls`** now also inspects `securitySchemes` entries for type
  `mutualTLS` (RFC 8705), not only the legacy `authentication.schemes` array.
- **`l3-skill-ids`** sharpened to verify all four A2A v1.0 REQUIRED skill
  fields (`id`, `name`, `description`, `tags`), not just `id`. Renamed for
  clarity. Same check id, more accurate definition.

### Out of scope

No new checks, no CLI UX changes, no batch / discovery additions, no
multi-interface (`additionalInterfaces`) handling.

### Verification

- `agentlair.dev` still grades **A** (92% overall) under the sharpened rubric.
- Synthetic v1.0 cards (`securitySchemes` map + `signatures[]` array)
  correctly trigger sharpened detection paths.
- Bearer-only `securitySchemes` correctly fails OAuth detection (was a
  false positive in v0.1.0).

## v0.1.0 — 2026-05-09 — initial release

- L1 (Identity), L2 (Authentication), L3 (Authorization), L4 (Behavioral
  Trust) audit framework.
- Probes for x402 / 401 / 402 status discrimination.
- CLI: single-target audit, batch comparison, `--json`, `--no-probe`.
