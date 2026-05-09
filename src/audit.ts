#!/usr/bin/env node
/**
 * a2a-trust-audit — Analyze the trust properties of an A2A agent card.
 *
 * Takes an agent endpoint URL, fetches /.well-known/agent.json (or agent-card.json),
 * checks identity / auth / authorization / behavioral trust properties, and scores
 * the result on a 0-100 scale across four layers:
 *   L1 Identity · L2 Authentication · L3 Authorization · L4 Behavioral Trust
 *
 * Usage:
 *   npx @agentlair/a2a-trust-audit https://agentlair.dev
 *   npx @agentlair/a2a-trust-audit https://agentlair.dev --json
 *   npx @agentlair/a2a-trust-audit ./local-card.json
 */

import { readFile } from 'node:fs/promises';

// ── types ────────────────────────────────────────────────────────────────────

interface AgentCard {
  schema_version?: string;
  name?: string;
  description?: string;
  url?: string;
  iconUrl?: string;
  version?: string;
  defaultInputModes?: string[];
  defaultOutputModes?: string[];
  capabilities?: Record<string, boolean>;
  skills?: Array<{
    id?: string;
    name?: string;
    description?: string;
    tags?: string[];
    examples?: string[];
  }>;
  // Legacy auth shape (A2A v0.2.5 and earlier):
  authentication?: {
    schemes?: string[];
    description?: string;
    credentials?: unknown;
  };
  // Canonical A2A v1.0 shape:
  securitySchemes?: Record<string, unknown>;
  security_schemes?: Record<string, unknown>; // snake-case variant some impls use
  contact?: { email?: string; url?: string };
  provider?: { organization?: string; url?: string };
  // trust extensions
  did?: string;
  jwks_uri?: string;
  jwks_url?: string;
  jwksUri?: string;
  trust_attestation?: {
    score?: number;
    level?: string;
    confidence?: number;
    computed_at?: string;
    trend?: string;
    self_reported?: boolean;
    trust_endpoint_template?: string;
  };
  audit_trail_url?: string;
  audit_trail_url_template?: string;
  card_signature?: string; // legacy JWS detached signature (single)
  signatures?: Array<{ protected?: string; signature?: string; header?: unknown }>; // A2A v1.0
  behavioral_monitoring?: unknown;
  [key: string]: unknown;
}

interface Check {
  id: string;
  layer: 'L1' | 'L2' | 'L3' | 'L4';
  name: string;
  pass: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  detail: string;
}

interface AuditResult {
  target: string;
  fetched_from: string;
  card: AgentCard | null;
  probe?: { status?: number; flavor?: 'x402' | 'auth' | 'open' | 'unknown'; x402_headers?: boolean };
  checks: Check[];
  scores: {
    L1_identity: number;
    L2_authentication: number;
    L3_authorization: number;
    L4_behavioral: number;
    overall: number;
  };
  grade: string;
  recommendations: string[];
}

// ── fetch card ───────────────────────────────────────────────────────────────

const WELL_KNOWN_PATHS = [
  '/.well-known/agent-card.json',
  '/.well-known/agent.json',
];

async function fetchCard(target: string): Promise<{ card: AgentCard; from: string }> {
  // local file
  if (target.endsWith('.json') && !target.startsWith('http')) {
    const text = await readFile(target, 'utf-8');
    return { card: JSON.parse(text), from: target };
  }

  const base = target.replace(/\/+$/, '');

  for (const path of WELL_KNOWN_PATHS) {
    try {
      const url = base + path;
      const res = await fetch(url, {
        headers: { Accept: 'application/json' },
        redirect: 'follow',
      });
      if (res.ok) {
        const card = (await res.json()) as AgentCard;
        return { card, from: url };
      }
    } catch {
      // try next
    }
  }

  throw new Error(`No agent card found at ${base} (tried ${WELL_KNOWN_PATHS.join(', ')})`);
}

// ── probe endpoint for 401 vs 402 ───────────────────────────────────────────
//
// The agent card is public. The skill endpoints behind it usually aren't.
// HTTP 401 = "you need an account" (auth gap, table-stakes).
// HTTP 402 = "pay per request" (x402 / Layer 2 payment-gated, skin-in-the-game
//   signal — caller commits before the agent acts).
//
// We probe `card.url` (or first skill endpoint hint) with a no-auth POST. If
// the agent is gated by x402, we typically get 402 immediately. If it's gated
// by API key, 401. If it returns 200 it's likely open or the probe hit a
// non-skill route.

function detectX402Headers(headers: Headers): boolean {
  const expose = headers.get('access-control-expose-headers') || '';
  const wwwAuth = headers.get('www-authenticate') || '';
  return /x[-_]?402[-_]?version/i.test(expose)
    || /x[-_]?payment[-_]?response/i.test(expose)
    || /x[-_]?payment[-_]?required/i.test(expose)
    || /payment/i.test(wwwAuth);
}

async function probeEndpoint(card: AgentCard): Promise<AuditResult['probe']> {
  if (!card.url) return { flavor: 'unknown' };

  const base = card.url.replace(/\/+$/, '');
  const candidates = [
    `${base}/v1/messages`,
    `${base}/v1/run`,
    `${base}/v1/invoke`,
    base,
  ];

  let firstStatus: number | undefined;
  let anyX402Headers = false;

  for (const url of candidates) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ probe: 'a2a-trust-audit' }),
        redirect: 'follow',
        signal: AbortSignal.timeout(5000),
      });
      if (firstStatus === undefined) firstStatus = res.status;
      if (detectX402Headers(res.headers)) anyX402Headers = true;

      if (res.status === 402) return { status: 402, flavor: 'x402', x402_headers: true };
      if (res.status === 401) {
        // If headers suggest x402 middleware is wired, prefer that signal.
        if (anyX402Headers) return { status: 401, flavor: 'x402', x402_headers: true };
        return { status: 401, flavor: 'auth', x402_headers: false };
      }
    } catch {
      // try next
    }
  }

  if (firstStatus === undefined) return { flavor: 'unknown' };
  if (firstStatus < 400) return { status: firstStatus, flavor: 'open', x402_headers: anyX402Headers };
  return { status: firstStatus, flavor: anyX402Headers ? 'x402' : 'unknown', x402_headers: anyX402Headers };
}

// ── checks ───────────────────────────────────────────────────────────────────

function runChecks(card: AgentCard, _from: string, probe?: AuditResult['probe']): Check[] {
  const checks: Check[] = [];

  const add = (c: Omit<Check, 'pass'> & { pass: boolean }) => checks.push(c as Check);

  // Resolve dual-shape fields up front so every check sees one truth.
  // A2A v1.0 prefers `securitySchemes` (camelCase, map). v0.2.5 used a nested
  // `authentication.schemes` array. Some impls emit snake_case `security_schemes`.
  const securitySchemesObj =
    (card.securitySchemes as Record<string, unknown> | undefined) ||
    (card.security_schemes as Record<string, unknown> | undefined);
  const securitySchemesValues = Object.values(securitySchemesObj || {}) as Array<{
    type?: string;
    scheme?: string;
  }>;

  // A2A v1.0: `signatures: AgentCardSignature[]`. Legacy: single `card_signature` (JWS).
  const hasSignaturesArray = Array.isArray(card.signatures) && card.signatures.length > 0;
  const hasLegacyCardSignature = !!card.card_signature;
  const hasCardSignature = hasSignaturesArray || hasLegacyCardSignature;

  // JWKS reference (RFC 7517, AgentLair extension to A2A core)
  const jwksRef = card.jwks_uri || card.jwks_url || card.jwksUri;

  // ── L1: Identity ──
  add({
    id: 'l1-name',
    layer: 'L1',
    name: 'Agent name declared',
    pass: !!card.name,
    severity: 'critical',
    detail: card.name ? `Name: "${card.name}"` : 'Missing agent name — consumers cannot identify this agent.',
  });

  add({
    id: 'l1-description',
    layer: 'L1',
    name: 'Description present',
    pass: !!card.description && card.description.length > 10,
    severity: 'high',
    detail: card.description
      ? `${card.description.length} chars`
      : 'No description — other agents cannot understand capabilities.',
  });

  add({
    id: 'l1-url',
    layer: 'L1',
    name: 'Base URL declared',
    pass: !!card.url,
    severity: 'critical', // A2A v1.0 marks `AgentCard.url` as REQUIRED
    detail: card.url || 'No URL — agents cannot reach this endpoint.',
  });

  add({
    id: 'l1-https',
    layer: 'L1',
    name: 'HTTPS endpoint',
    pass: card.url?.startsWith('https://') ?? false,
    severity: 'critical',
    detail: card.url?.startsWith('https://') ? 'HTTPS' : 'Not HTTPS — transport is unencrypted.',
  });

  add({
    id: 'l1-version',
    layer: 'L1',
    name: 'Version specified',
    pass: !!card.version,
    severity: 'medium', // A2A v1.0 marks `AgentCard.version` as REQUIRED
    detail: card.version ? `v${card.version}` : 'No version — consumers cannot pin or track changes.',
  });

  // SUBTRACTED 2026-05-09 (v0.1.1): `l1-schema` removed — A2A v1.0 has no
  // `schema_version` field at all. The "0.8" sometimes seen in cards
  // (including AgentLair's) is non-canonical. Spec uses `version` (already
  // checked above) and `protocolVersion` on `AgentInterface`. Subtraction
  // over addition: see RUBRIC.md.

  add({
    id: 'l1-contact',
    layer: 'L1',
    // AgentLair extension — A2A v1.0 has no `contact` field. Useful for
    // vulnerability disclosure but not part of the canonical schema.
    name: 'Contact information (vulnerability disclosure)',
    pass: !!(card.contact?.email || card.contact?.url),
    severity: 'low',
    detail: card.contact
      ? `Email: ${card.contact.email || '—'}, URL: ${card.contact.url || '—'}`
      : 'No contact info — vulnerability reports have nowhere to go.',
  });

  add({
    id: 'l1-provider',
    layer: 'L1',
    name: 'Provider/organization declared',
    pass: !!(card.provider?.organization || card.provider?.url),
    severity: 'medium',
    detail: card.provider
      ? `Org: ${card.provider.organization || '—'}`
      : 'No provider — unclear who operates this agent.',
  });

  const hasDid = !!card.did || Object.values(card).some(
    v => typeof v === 'string' && v.startsWith('did:')
  );
  add({
    id: 'l1-did',
    layer: 'L1',
    name: 'DID (Decentralized Identifier)',
    pass: hasDid,
    severity: 'high',
    detail: hasDid
      ? `DID present — agent has decentralized identity.`
      : 'No DID — identity tied to DNS only. No portable, self-sovereign identity.',
  });

  // ── L2: Authentication ──
  // A2A v1.0 prefers top-level `securitySchemes` (map). v0.2.5 used a nested
  // `authentication.schemes` array. Accept both.
  const schemes = card.authentication?.schemes || [];
  const hasAuthDeclared = schemes.length > 0 || !!securitySchemesObj;
  add({
    id: 'l2-auth-declared',
    layer: 'L2',
    name: 'Authentication scheme declared',
    pass: hasAuthDeclared,
    severity: 'critical',
    detail: schemes.length > 0
      ? `Schemes (legacy authentication.schemes): ${schemes.join(', ')}`
      : securitySchemesObj
        ? `securitySchemes (A2A v1.0): ${Object.keys(securitySchemesObj).join(', ')}`
        : 'No authentication — any caller can interact without proof of identity.',
  });

  // OAuth/OIDC detection: legacy schemes array + v1.0 securitySchemes typed
  // entries. Per OpenAPI / A2A v1.0, security scheme `type` values include
  // `oauth2` and `openIdConnect`. The previous `|| !!card.security_schemes`
  // fallback was over-eager — bearer-only securitySchemes does not imply
  // OAuth. Subtraction in spirit: removed the false-positive arm.
  const hasOAuthInSecuritySchemes = securitySchemesValues.some(s => {
    const t = (s?.type || '').toLowerCase();
    return t === 'oauth2' || t === 'openidconnect' || t === 'openid';
  });
  const hasOAuth = schemes.some(s =>
    ['oauth2', 'openid', 'oidc'].includes(s.toLowerCase())
  ) || hasOAuthInSecuritySchemes;
  add({
    id: 'l2-oauth',
    layer: 'L2',
    name: 'OAuth 2.0 or OpenID Connect',
    pass: hasOAuth,
    severity: 'medium',
    detail: hasOAuth
      ? 'Supports OAuth/OIDC — standard identity federation.'
      : 'No OAuth/OIDC — limited to API keys or bearer tokens.',
  });

  add({
    id: 'l2-jwks',
    layer: 'L2',
    name: 'JWKS endpoint referenced',
    pass: !!jwksRef,
    severity: 'high',
    detail: jwksRef
      ? `JWKS: ${jwksRef}`
      : 'No JWKS reference — consumers cannot verify signed tokens offline.',
  });

  add({
    id: 'l2-card-signed',
    layer: 'L2',
    name: 'Agent card is signed',
    // A2A v1.0: `signatures: AgentCardSignature[]`. Legacy: single
    // `card_signature` JWS string. Accept both.
    pass: hasCardSignature,
    severity: 'critical',
    detail: hasSignaturesArray
      ? `Card has ${card.signatures!.length} JWS signature(s) (A2A v1.0 \`signatures[]\`) — integrity verifiable.`
      : hasLegacyCardSignature
        ? 'Card has cryptographic signature (legacy `card_signature`) — integrity verifiable.'
        : 'UNSIGNED CARD — anyone who controls the endpoint can swap capabilities, skills, or identity claims. This is the #1 gap in A2A.',
  });

  // x402 — strong signal of payment-gated commitment.
  // Detected either through a 402 probe response, or via an explicit field in
  // the card. x402 means the caller pays per request — skin in the game on
  // both sides, not just the operator's.
  const hasX402Field = Object.keys(card).some(k =>
    k === 'x402' || k === 'payment_schemes' || k === 'payment_required' || k === 'pricing'
  );
  const probedX402 = probe?.flavor === 'x402';
  const hasX402 = hasX402Field || probedX402;
  add({
    id: 'l2-x402',
    layer: 'L2',
    name: 'x402 payment-gated (skin in the game)',
    pass: hasX402,
    severity: 'high',
    detail: probe?.status === 402
      ? `Endpoint returned 402 Payment Required — x402 confirmed via probe.`
      : probedX402 && probe?.x402_headers
        ? `x402 middleware detected via response headers (X-402-Version / X-Payment-Response exposed). Status ${probe.status}.`
        : hasX402Field
          ? 'Card declares x402/pricing field — payment-gated calls.'
          : probe?.flavor === 'auth'
            ? `Endpoint returned ${probe.status} (auth gap, not payment-gated). x402 = strong commitment signal; standard auth is table-stakes.`
            : 'No x402 / payment-gating detected. Free endpoints have no caller-side commitment cost.',
  });

  // mTLS detection: legacy schemes array + v1.0 securitySchemes typed entries.
  // OpenAPI/A2A v1.0 uses scheme type `mutualTLS` (RFC 8705).
  const hasMtlsInSecuritySchemes = securitySchemesValues.some(s => {
    const t = (s?.type || '').toLowerCase();
    return t === 'mutualtls' || t === 'mtls';
  });
  const hasMtls = schemes.some(s => s.toLowerCase().includes('mtls') || s.toLowerCase().includes('mutual'))
    || hasMtlsInSecuritySchemes;
  add({
    id: 'l2-mtls',
    layer: 'L2',
    name: 'Mutual TLS support',
    pass: hasMtls,
    severity: 'low',
    detail: hasMtls
      ? 'mTLS available — strong transport-layer authentication.'
      : 'No mTLS — relying on application-layer auth only.',
  });

  // ── L3: Authorization ──
  const skills = card.skills || [];
  add({
    id: 'l3-skills',
    layer: 'L3',
    name: 'Skills/capabilities defined',
    pass: skills.length > 0,
    severity: 'high',
    detail: skills.length > 0
      ? `${skills.length} skills declared: ${skills.map(s => s.id || s.name).join(', ')}`
      : 'No skills — consumers cannot scope interactions.',
  });

  // A2A v1.0 marks `id`, `name`, `description`, and `tags` as REQUIRED on
  // every AgentSkill. Sharpen the existing check to verify all four — it's
  // the same rubric question ("can a consumer scope and discover this
  // capability?") with a more accurate definition.
  const skillsRequiredFields = (s: { id?: string; name?: string; description?: string; tags?: string[] }) =>
    !!s.id && !!s.name && !!s.description && Array.isArray(s.tags) && s.tags.length > 0;
  const allSkillsComplete = skills.every(skillsRequiredFields);
  const idsCount = skills.filter(s => !!s.id).length;
  add({
    id: 'l3-skill-ids',
    layer: 'L3',
    name: 'Skills have required fields (id, name, description, tags)',
    pass: skills.length === 0 || allSkillsComplete,
    severity: 'medium',
    detail: allSkillsComplete
      ? `All ${skills.length} skills declare id + name + description + tags (A2A v1.0 required fields).`
      : `${idsCount}/${skills.length} skills have ids; some are missing required fields (id, name, description, tags per A2A v1.0).`,
  });

  add({
    id: 'l3-io-modes',
    layer: 'L3',
    name: 'Input/output modes specified',
    pass: !!(card.defaultInputModes?.length && card.defaultOutputModes?.length),
    severity: 'medium',
    detail: card.defaultInputModes
      ? `In: ${card.defaultInputModes.join(', ')} · Out: ${card.defaultOutputModes?.join(', ')}`
      : 'No I/O modes — interop risk with multi-modal agents.',
  });

  add({
    id: 'l3-capabilities',
    layer: 'L3',
    name: 'Capabilities explicitly declared',
    pass: !!card.capabilities && Object.keys(card.capabilities).length > 0,
    severity: 'medium',
    detail: card.capabilities
      ? `Capabilities: ${Object.entries(card.capabilities).map(([k, v]) => `${k}=${v}`).join(', ')}`
      : 'No capabilities object — defaults unknown.',
  });

  // ── L4: Behavioral Trust ──
  add({
    id: 'l4-trust-attestation',
    layer: 'L4',
    name: 'Trust attestation present',
    pass: !!card.trust_attestation,
    severity: 'critical',
    detail: card.trust_attestation
      ? card.trust_attestation.score !== undefined
        ? `Score: ${card.trust_attestation.score}/100, Level: ${card.trust_attestation.level || '—'}, Confidence: ${card.trust_attestation.confidence ?? '—'}`
        : card.trust_attestation.trust_endpoint_template
          ? `Trust endpoint template: ${card.trust_attestation.trust_endpoint_template}${card.trust_attestation.self_reported ? ' (self-reported — third-party attestation is stronger)' : ''}`
          : 'Trust attestation declared.'
      : 'NO TRUST ATTESTATION — no behavioral evidence. This agent has identity but no track record. The A2A spec has no standard for this.',
  });

  // Accept either a static audit_trail_url or a URI template (RFC 6570).
  // Templates like `https://agentlair.dev/v1/audit/{jti}` are stronger because
  // they let consumers fetch the audit record for a specific transaction (JTI
  // = JWT ID) rather than scrolling through a global feed.
  const hasAuditTrail = !!card.audit_trail_url || !!card.audit_trail_url_template;
  add({
    id: 'l4-audit-trail',
    layer: 'L4',
    name: 'Audit trail URL',
    pass: hasAuditTrail,
    severity: 'high',
    detail: card.audit_trail_url
      ? `Audit trail: ${card.audit_trail_url}`
      : card.audit_trail_url_template
        ? `Audit trail template (per-transaction): ${card.audit_trail_url_template}`
        : 'No audit trail — actions are unverifiable after the fact.',
  });

  const hasBehavioral = Object.keys(card).some(k =>
    k.includes('behavioral') || k.includes('telemetry') || k.includes('monitoring')
  );
  add({
    id: 'l4-behavioral-ref',
    layer: 'L4',
    name: 'Behavioral monitoring reference',
    pass: hasBehavioral,
    severity: 'high',
    detail: hasBehavioral
      ? 'References behavioral monitoring — runtime trust is tracked.'
      : 'No behavioral monitoring — trust is point-in-time only. TOCTOU gap: verified at check ≠ behavior at use.',
  });

  const hasDelegation = Object.keys(card).some(k =>
    k.includes('delegation') || k.includes('provenance') || k.includes('chain')
  );
  add({
    id: 'l4-delegation',
    layer: 'L4',
    name: 'Delegation/provenance chain',
    pass: hasDelegation,
    severity: 'medium',
    detail: hasDelegation
      ? 'Delegation chain present — sub-agent provenance verifiable.'
      : 'No delegation chain — if this agent spawns sub-agents, their provenance is unverifiable.',
  });

  return checks;
}

// ── scoring ──────────────────────────────────────────────────────────────────

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 1,
};

function score(checks: Check[]): AuditResult['scores'] {
  const byLayer = (layer: string) => {
    const layerChecks = checks.filter(c => c.layer === layer);
    if (layerChecks.length === 0) return 0;

    const maxScore = layerChecks.reduce((s, c) => s + SEVERITY_WEIGHT[c.severity], 0);
    const earned = layerChecks
      .filter(c => c.pass)
      .reduce((s, c) => s + SEVERITY_WEIGHT[c.severity], 0);

    return Math.round((earned / maxScore) * 100);
  };

  const l1 = byLayer('L1');
  const l2 = byLayer('L2');
  const l3 = byLayer('L3');
  const l4 = byLayer('L4');
  const overall = Math.round(l1 * 0.2 + l2 * 0.3 + l3 * 0.15 + l4 * 0.35);

  return {
    L1_identity: l1,
    L2_authentication: l2,
    L3_authorization: l3,
    L4_behavioral: l4,
    overall,
  };
}

function grade(overall: number): string {
  if (overall >= 90) return 'A';
  if (overall >= 80) return 'B';
  if (overall >= 65) return 'C';
  if (overall >= 50) return 'D';
  return 'F';
}

function recommendations(checks: Check[]): string[] {
  const recs: string[] = [];
  const failed = checks.filter(c => !c.pass).sort(
    (a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity]
  );

  for (const c of failed.slice(0, 8)) {
    switch (c.id) {
      case 'l2-card-signed':
        recs.push('Sign your agent card with JWS (Ed25519 or ECDSA). This is the single highest-impact fix — it prevents card tampering and proves endpoint control.');
        break;
      case 'l4-trust-attestation':
        recs.push('Add a trust_attestation field with behavioral score. Services like AgentLair (agentlair.dev) provide cross-org behavioral trust that embeds directly in agent cards and AATs.');
        break;
      case 'l2-x402':
        recs.push('Consider x402 payment-gating for skill endpoints. A 402 response shifts commitment to the caller — strong signal that requests are not spam. See agentlair.dev for an x402 reference implementation.');
        break;
      case 'l1-did':
        recs.push('Add a DID (did:web or did:key) for portable, self-sovereign identity that survives DNS changes.');
        break;
      case 'l2-jwks':
        recs.push('Publish a JWKS endpoint and reference it in the card so consumers can verify tokens offline.');
        break;
      case 'l4-audit-trail':
        recs.push('Expose an audit trail URL — either a static endpoint or a URI template (RFC 6570) like /v1/audit/{jti}. Per-transaction templates beat global feeds.');
        break;
      case 'l4-behavioral-ref':
        recs.push('Reference a behavioral monitoring endpoint. Point-in-time auth ≠ runtime trust (TOCTOU gap).');
        break;
      case 'l2-oauth':
        recs.push('Support OAuth 2.0 or OpenID Connect for standard identity federation across organizations.');
        break;
      case 'l1-provider':
        recs.push('Declare a provider/organization field so consumers know who operates this agent.');
        break;
      case 'l4-delegation':
        recs.push('Add a delegation chain so sub-agent provenance is cryptographically verifiable.');
        break;
      default:
        recs.push(`Fix: ${c.name} — ${c.detail}`);
    }
  }

  return recs;
}

// ── display ──────────────────────────────────────────────────────────────────

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  gray: '\x1b[90m',
};

function display(result: AuditResult) {
  const { card, checks, scores: s } = result;

  console.log();
  console.log(`${C.bold}${C.cyan}A2A Trust Audit${C.reset}`);
  console.log(`${C.dim}─────────────────────────────────────────────${C.reset}`);
  console.log(`${C.bold}Target:${C.reset} ${result.target}`);
  console.log(`${C.bold}Fetched:${C.reset} ${result.fetched_from}`);
  if (card?.name) console.log(`${C.bold}Agent:${C.reset} ${card.name} ${card.version ? `v${card.version}` : ''}`);
  if (result.probe?.flavor && result.probe.flavor !== 'unknown') {
    const probeColor = result.probe.flavor === 'x402' ? C.green : result.probe.flavor === 'auth' ? C.yellow : C.gray;
    console.log(`${C.bold}Probe:${C.reset} ${probeColor}${result.probe.status} ${result.probe.flavor}${C.reset}`);
  }
  console.log();

  // scores bar
  const bar = (label: string, val: number) => {
    const w = 30;
    const filled = Math.round((val / 100) * w);
    const color = val >= 80 ? C.green : val >= 50 ? C.yellow : C.red;
    const b = color + '█'.repeat(filled) + C.dim + '░'.repeat(w - filled) + C.reset;
    console.log(`  ${label.padEnd(22)} ${b} ${color}${val}%${C.reset}`);
  };

  console.log(`${C.bold}Scores${C.reset}`);
  bar('L1 Identity', s.L1_identity);
  bar('L2 Authentication', s.L2_authentication);
  bar('L3 Authorization', s.L3_authorization);
  bar('L4 Behavioral Trust', s.L4_behavioral);
  console.log(`${C.dim}  ─────────────────────────────────────────────${C.reset}`);

  const gradeColor = result.grade === 'A' ? C.green : result.grade <= 'C' ? C.yellow : C.red;
  bar('OVERALL', s.overall);
  console.log(`  ${C.bold}Grade:${C.reset} ${gradeColor}${C.bold}${result.grade}${C.reset}`);
  console.log();

  // checks
  console.log(`${C.bold}Checks${C.reset}`);
  let currentLayer = '';
  for (const c of checks) {
    if (c.layer !== currentLayer) {
      currentLayer = c.layer;
      const layerNames: Record<string, string> = {
        L1: 'Identity',
        L2: 'Authentication',
        L3: 'Authorization',
        L4: 'Behavioral Trust',
      };
      console.log(`\n  ${C.bold}${C.blue}${c.layer} — ${layerNames[c.layer]}${C.reset}`);
    }
    const icon = c.pass ? `${C.green}✓${C.reset}` : `${C.red}✗${C.reset}`;
    const sevColor = c.severity === 'critical' ? C.red :
      c.severity === 'high' ? C.yellow :
      c.severity === 'medium' ? C.magenta : C.gray;
    console.log(`  ${icon} ${c.name.padEnd(38)} ${sevColor}[${c.severity}]${C.reset}`);
    if (!c.pass) {
      console.log(`    ${C.dim}${c.detail}${C.reset}`);
    }
  }
  console.log();

  // recommendations
  if (result.recommendations.length > 0) {
    console.log(`${C.bold}${C.yellow}Recommendations${C.reset}`);
    for (let i = 0; i < result.recommendations.length; i++) {
      console.log(`  ${C.bold}${i + 1}.${C.reset} ${result.recommendations[i]}`);
    }
    console.log();
  }

  // verdict
  if (s.L4_behavioral === 0) {
    console.log(`${C.bold}${C.red}Verdict:${C.reset} This agent card has ${C.bold}no behavioral trust layer${C.reset}.`);
    console.log(`Identity (L1-L2) tells you WHO. Authorization (L3) tells you WHAT.`);
    console.log(`But neither tells you HOW this agent actually behaves in production.`);
    console.log(`${C.dim}The A2A protocol has no standard for L4. This is the gap.${C.reset}`);
    console.log();
  }
}

// ── summary table (batch mode) ──────────────────────────────────────────────

function displaySummaryTable(results: AuditResult[]) {
  console.log();
  console.log(`${C.bold}${C.cyan}A2A Trust Audit — Comparison${C.reset}`);
  console.log(`${C.dim}${'─'.repeat(88)}${C.reset}`);
  console.log(
    `  ${'Agent'.padEnd(24)} ${'L1'.padEnd(6)} ${'L2'.padEnd(6)} ${'L3'.padEnd(6)} ${'L4'.padEnd(6)} ${'Overall'.padEnd(9)} Grade`
  );
  console.log(`${C.dim}${'─'.repeat(88)}${C.reset}`);

  for (const r of results) {
    const name = (r.card?.name || r.target).slice(0, 22).padEnd(24);
    const colorVal = (v: number) => {
      const c_ = v >= 80 ? C.green : v >= 50 ? C.yellow : C.red;
      return `${c_}${String(v).padStart(3)}%${C.reset}`;
    };
    const gc = r.grade === 'A' ? C.green : r.grade <= 'C' ? C.yellow : C.red;
    console.log(
      `  ${name} ${colorVal(r.scores.L1_identity)}  ${colorVal(r.scores.L2_authentication)}  ${colorVal(r.scores.L3_authorization)}  ${colorVal(r.scores.L4_behavioral)}  ${colorVal(r.scores.overall)}    ${gc}${C.bold}${r.grade}${C.reset}`
    );
  }

  console.log(`${C.dim}${'─'.repeat(88)}${C.reset}`);

  // L4 verdict
  const allZeroL4 = results.every(r => r.scores.L4_behavioral === 0);
  if (allZeroL4) {
    console.log();
    console.log(`${C.bold}${C.red}Every agent scored 0% on L4 (Behavioral Trust).${C.reset}`);
    console.log(`The A2A protocol has no standard for it. Identity and authorization exist. Behavioral trust doesn't.`);
  }
  console.log();
}

// ── main ─────────────────────────────────────────────────────────────────────

async function auditOne(target: string, options: { skipProbe?: boolean } = {}): Promise<AuditResult> {
  const { card, from } = await fetchCard(target);

  let probe: AuditResult['probe'] = { flavor: 'unknown' };
  if (!options.skipProbe && (target.startsWith('http') || (card.url && card.url.startsWith('http')))) {
    probe = await probeEndpoint(card);
  }

  const checks = runChecks(card, from, probe);
  const scores = score(checks);
  const g = grade(scores.overall);
  const recs = recommendations(checks);

  return {
    target,
    fetched_from: from,
    card,
    probe,
    checks,
    scores,
    grade: g,
    recommendations: recs,
  };
}

async function main() {
  const args = process.argv.slice(2);
  const jsonMode = args.includes('--json');
  const helpMode = args.includes('--help') || args.includes('-h');
  const noProbe = args.includes('--no-probe');
  const targets = args.filter(a => !a.startsWith('--'));

  if (helpMode || targets.length === 0) {
    console.log(`${C.bold}a2a-trust-audit${C.reset} — Score any A2A agent card on identity, auth, authorization, and behavioral trust.`);
    console.log();
    console.log(`${C.bold}Usage:${C.reset}`);
    console.log('  npx @agentlair/a2a-trust-audit <url-or-file> [url2 url3 ...] [options]');
    console.log();
    console.log(`${C.bold}Options:${C.reset}`);
    console.log('  --json       Output raw JSON instead of formatted display');
    console.log('  --no-probe   Skip the 401/402 endpoint probe (faster, less signal)');
    console.log('  --help, -h   Show this help');
    console.log();
    console.log(`${C.bold}Examples:${C.reset}`);
    console.log('  npx @agentlair/a2a-trust-audit https://agentlair.dev');
    console.log('  npx @agentlair/a2a-trust-audit https://agentlair.dev --json');
    console.log('  npx @agentlair/a2a-trust-audit ./my-agent-card.json');
    console.log('  npx @agentlair/a2a-trust-audit https://agent-a.com https://agent-b.com    # compare');
    console.log();
    console.log(`${C.bold}Layers:${C.reset}`);
    console.log('  L1 Identity         Name, DID, provider, contact');
    console.log('  L2 Authentication   OAuth, JWKS, card signature, x402, mTLS');
    console.log('  L3 Authorization    Skills, capabilities, I/O modes');
    console.log('  L4 Behavioral       Trust score, audit trail, monitoring');
    console.log();
    console.log('Checks 20+ properties. Weights by severity. Grades A-F.');
    console.log(`${C.dim}The L4 score is usually zero. That's the point.${C.reset}`);
    process.exit(helpMode ? 0 : 1);
  }

  const results: AuditResult[] = [];

  for (const target of targets) {
    try {
      const result = await auditOne(target, { skipProbe: noProbe });
      results.push(result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`${C.red}Error${C.reset} (${target}): ${msg}`);
      if (targets.length === 1) process.exit(1);
    }
  }

  if (results.length === 0) process.exit(1);

  if (jsonMode) {
    console.log(JSON.stringify(results.length === 1 ? results[0] : results, null, 2));
  } else if (results.length === 1) {
    display(results[0]);
  } else {
    // show individual reports then summary
    for (const r of results) display(r);
    displaySummaryTable(results);
  }
}

main();
