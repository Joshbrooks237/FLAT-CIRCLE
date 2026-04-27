import { useState, useEffect, useCallback } from "react";

export type AITier = "openai" | "anthropic" | "ollama" | "static";
export type ThreatClass = "script-kiddie" | "automated-scanner" | "sophisticated-actor" | "competitor-scraper" | "nation-state";

export interface ThreatEvent {
  id: string;
  type: "honeypot.triggered" | "honeypot.recursive.descent" | "canary.fired" | "behavioral.anomaly" | "session.shadowed" | "threat.classified" | "merkle.root.updated" | "provider.failover" | "campaign.matched" | "tarpit.connection.absorbed" | "flood.detected" | "upstream.escalated"
    | "dependency.mismatch.detected"
    | "secret.redacted"
    | "authn.anomaly.detected"
    | "dns.record.unrecognized"
    | "dns.takeover.suspected"
    | "client.integrity.low"
    | "exfiltration.velocity.exceeded"
    | "ai.injection.attempt"
  | "forensic.stream.flushed"
  | "forensic.stream.error"
  | "incident.package.sealed"
  | "compliance.report.generated"
  | "legal.hold.activated"
  | "legal.hold.released";
  timestamp: number;
  ip: string;
  sessionId: string;
  depth?: number;
  threatClass?: ThreatClass;
  narration: string;
  providerTier: AITier;
}

export interface ShadowSession {
  id: string;
  ip: string;
  startedAt: number;
  threatClass: ThreatClass;
  depth: number;
  requestCount: number;
}

export interface Mod7State {
  honeypot: number;
  temporal: number;
  entropy: number;
  routes: number;
  merkle: number;
}

export interface MerkleState {
  root: string;
  leafCount: number;
  lastUpdated: number;
  tampered: boolean;
}

export interface LayerState {
  id: number;
  name: string;
  enabled: boolean;
  hitCount: number;
}

export interface TarpitNodeState {
  id: string;
  ip: string;
  connectedAt: number;
  mod7Seed: number;
  bytesDelivered: number;
}

export type UpstreamStatus = "active" | "standby" | "not-configured";

export interface Layer14State {
  floodActive: boolean;
  activeTarpitConnections: TarpitNodeState[];
  absorptionCapacityPct: number;
  upstreamStatus: UpstreamStatus;
  upstreamProvider: "cloudflare" | "aws-shield" | "custom-webhook" | null;
  bytesWasted: number;
}

export interface DependencyIntegrityState {
  status: "clean" | "unverified" | "compromised";
  packageCount: number;
  lastVerifiedAt: number;
  mismatchCount: number;
}

export interface SecretsSentinelState {
  totalRedacted: number;
  recentRedactions: Array<{ field: string; patternType: string; timestamp: number }>;
}

export type AuthAnomalyClass = "credential-compromise" | "malicious-insider" | "automated-scraping" | "privilege-escalation" | "lateral-movement" | "bulk-exfiltration" | "unknown";

export interface FlaggedIdentity {
  id: string;
  identityId: string;
  anomalyClass: AuthAnomalyClass;
  riskScore: number;
  detectedAt: number;
  requestCount: number;
}

export interface AuthnAnomalyState {
  flaggedIdentities: FlaggedIdentity[];
  totalAnomalies: number;
}

export type DNSPointStatus = "verified" | "unrecognized" | "flagged";

export interface DNSPoint {
  id: string;
  hostname: string;
  status: DNSPointStatus;
  angleDeg: number;
  distancePct: number;
}

export interface DNSIntegrityState {
  points: DNSPoint[];
  lastScanAt: number;
  flaggedCount: number;
}

export interface ClientIntegrityState {
  highCount: number;
  mediumCount: number;
  lowCount: number;
  routedToHoneypot: number;
}

export interface ExfiltrationState {
  tideLevel: number; // 0–100, slow-rising
  identities: Array<{ id: string; identityId: string; bytesLast24h: number; thresholdBytes: number }>;
  totalExceeded: number;
}

export interface AIInjectionState {
  totalAttempts: number;
  recentAttempts: Array<{ id: string; timestamp: number; pattern: string; sanitized: boolean }>;
}

export type ForensicStreamStatus = "streaming" | "buffered" | "unreachable";

export interface Layer22State {
  streamStatus: ForensicStreamStatus;
  exportedLeafCount: number;
  incidentPackageCount: number;
  lastComplianceReportAt: number | null;
  nextComplianceReportAt: number | null;
  legalHoldActive: boolean;
  legalHoldSince: number | null;
  legalHoldReason: string | null;
}

export interface DashboardState {
  events: ThreatEvent[];
  shadowSessions: ShadowSession[];
  mod7: Mod7State;
  merkle: MerkleState;
  providerTier: AITier;
  providerReason: string | null;
  layers: LayerState[];
  stats: {
    honeypotHits: number;
    shadowedSessions: number;
    canariesFired: number;
    requestsBlocked: number;
    merkleLeaves: number;
  };
  slimeEvents: SlimeEvent[];
  proxyActive: boolean;
  layer14: Layer14State;
  layer15: DependencyIntegrityState;
  layer16: SecretsSentinelState;
  layer17: AuthnAnomalyState;
  layer18: DNSIntegrityState;
  layer19: ClientIntegrityState;
  layer20: ExfiltrationState;
  layer21: AIInjectionState;
  layer22: Layer22State;
}

export interface SlimeEvent {
  id: string;
  type: "ripple" | "flare" | "darken" | "ring";
  x: number;
  y: number;
  timestamp: number;
}

const TARPIT_NARRATIONS = [
  "Flood cluster detected — {count} IPs synchronized arrival pattern, CV {cv}. Progressive degradation engaged. Connections held open.",
  "Volumetric spike from {ip} cluster. {rps} req/s. Tarpit stage 2 active. Attacker tooling is waiting for a response that arrives in geological time.",
  "Botnet flood pattern confirmed. Slow-drip responses initiated. {count} connections tarpitted. {bytes} bytes consumed for zero attacker gain.",
  "Low-variation timing signature — botnet fingerprint. Sessions cloned to Layer 9. Tarpit absorbing at mod7 seed {seed}/6.",
  "Flood cluster {count} IPs. Peak {rps} req/s. Upstream absorber on standby. Local capacity {pct}% utilized. Membrane holds.",
];

const NARRATIONS = {
  "honeypot.triggered": [
    "Automated scanner using modified Burp Suite profile has entered the honeypot mesh. Classified: low-sophistication bot. Serving fabricated health endpoint.",
    "Probe from {ip} matched active honeypot slot 3/7. Stack fingerprint suggests PHP-Apache. Serving fabricated admin panel response.",
    "Bot pattern detected — sequential path enumeration at 340 req/min. Honeypot layer 1 engaged. Decoy: fake GraphQL schema.",
    "CVE scanner (Nuclei signature) hit credential honeypot. Serving plausible but fabricated API key structure.",
  ],
  "honeypot.recursive.descent": [
    "Persistent automated campaign has descended to recursive layer {depth}. Classified: sophisticated actor. Serving fabricated credential schema.",
    "Session {session} now at depth {depth}. Goal inference: API mapping (87% confidence). Decoy sophistication escalating.",
    "Nation-state pattern actor from {ip} at recursive layer {depth}. Serving deeply elaborated fake data architecture. There is no bottom.",
    "Script kiddie followed breadcrumb to layer {depth}. Serving fake database dump. They believe they found something.",
  ],
  "canary.fired": [
    "CANARY FIRED — Token issued to session {session} detected in unauthorized context. Full Merkle chain of custody established.",
    "Canary token from 6h ago appeared in external HTTP request. Leak traced to IP {ip}. Chain of custody cryptographically proven.",
    "Asset canary triggered — embedded token from session {session} appeared in competitor domain scan.",
  ],
  "behavioral.anomaly": [
    "Behavioral anomaly detected — cosine distance 0.72 from baseline. Session {session} rerouted to honeypot mesh.",
    "Request pattern diverged from learned baseline. Velocity: 12x normal. Session silently redirected.",
    "Embedding vector divergence exceeded threshold (0.41). Automated tooling suspected. Shadow session initiated.",
  ],
  "session.shadowed": [
    "Session {session} crossed anomaly threshold. Clone created. Actor continues interacting with shadow environment. Real app untouched.",
    "High-threat session isolated to shadow layer. AI classification in progress. Actor has no indication they are contained.",
    "Session shadowed after {depth} honeypot interactions. Actor classified: sophisticated automated scanner.",
  ],
  "threat.classified": [
    "Session {session} classified: {class}. Sophistication score: {score}/10. Decoy strategy escalated to match threat level.",
    "AI classification complete — {class} pattern confirmed. Campaign signature matched across 3 other installations.",
    "Threat actor classified as {class}. Response strategy updated in real time.",
  ],
  "merkle.root.updated": [
    "Merkle root recomputed at mod7 boundary. {leaves} leaves. Root: {root}. Chain intact.",
    "Session tree updated. {leaves} events recorded. Root hash verified. Tamper status: clean.",
  ],
  "provider.failover": [
    "OpenAI quota exceeded. Cascading to Anthropic Claude. Protection continues uninterrupted.",
    "Primary AI provider unavailable. Falling back to local Ollama instance. All layers remain active.",
    "Provider failover: GPT-4o → Claude. Reason: rate limit. Recovery attempt in 5 minutes.",
  ],
  "campaign.matched": [
    "Probe pattern matches known campaign 'SilkRoad-7' seen across 14 other Flat Circle installations. Escalating immediately.",
    "Attack signature matched collective intelligence database. Campaign: automated credential harvesting wave. Origin cluster identified.",
  ],
  "tarpit.connection.absorbed": TARPIT_NARRATIONS,
  "flood.detected": TARPIT_NARRATIONS,
  "upstream.escalated": [
    "Local absorption capacity exceeded. Upstream escalation triggered. Cloudflare standing by. The flood spends itself against the absorber.",
    "Traffic volume crossed upstream threshold. AWS Shield integration active. Tarpit continues. Interior untouched.",
  ],
  "secret.redacted": [
    "Outbound response body contained AWS credential pattern. Redacted before transmission. Merkle leaf recorded. The leak almost happened.",
    "JWT token detected in JSON response field 'token'. Entropy score 5.8 bits/char. Redacted. This was not the intended response field.",
    "High-entropy string (5.2 bits/char) detected in response header X-Debug-Key. Redacted. Context: debug endpoint left active in production.",
    "Private key block (PEM format) detected in response body. Redacted. Full chain of custody recorded in Merkle tree.",
  ],
  "authn.anomaly.detected": [
    "Authenticated identity {identity} accessed {count} records in the last hour. Baseline: {baseline}/hr. Anomaly score: {score}. Shadow session activated.",
    "Session {session} from {ip} — resource access pattern outside known scope. Privilege escalation attempt signature. Layer 9 clone initiated.",
    "Identity {identity} accessing endpoints not in six-month behavioral baseline. Cosine distance: {score}. Classified: lateral movement.",
    "Bulk data access pattern detected for {identity}. {count} records in {window}. This is not how a person moves. AI classification: automated scraping through legitimate credentials.",
  ],
  "dns.record.unrecognized": [
    "Subdomain {host} resolves to resource not in recognized infrastructure. Pending verification. Could be new deployment. Could be something else.",
    "CNAME {host} points to {target} — target not in known-good set. Monitoring. The quiet ones are the ones that cost you.",
  ],
  "dns.takeover.suspected": [
    "CNAME {host} points to {target} — target appears to be unclaimed. Potential subdomain takeover. Immediate alert dispatched.",
    "Subdomain {host} DNS target is a deprovisioned service. Takeover window open. The sign is still up. The building is empty.",
  ],
  "client.integrity.low": [
    "Client from {ip} scored {score}/1.0 integrity. JA3 mismatch with claimed User-Agent. Routed to honeypot mesh. They think they're hitting the real app.",
    "HTTP/2 fingerprint inconsistency detected — claimed Chrome, negotiated like Python requests. Integrity score: {score}. Honeypot engaged.",
    "Headless browser signature detected from {ip}. Integrity: {score}. Tool: likely Playwright. Route: honeypot layer 2.",
  ],
  "exfiltration.velocity.exceeded": [
    "Identity {identity} transferred {bytes} in the last 24 hours. Threshold: {threshold}. This is not analysis. This is extraction. Layer 9 shadow activated.",
    "Cumulative transfer velocity for {identity} exceeds monthly baseline by {mult}x. Pattern consistent with slow-exfiltration campaign. Escalating.",
    "Data transfer rate for {identity}: {rate} MB/hr sustained over {hours} hours. No legitimate use case explains this. AI classification: exfiltration.",
  ],
  "forensic.stream.flushed": [
    "Forensic stream flushed — {count} leaves exported to {target}. Total exported: {total}. Append-only. Chain intact.",
    "{count} Merkle leaves streamed to forensic export target. Root hash included in each record. Nothing was overwritten.",
    "Stream buffer flushed. {count} forensic records committed. The export is the permanent record.",
  ],
  "forensic.stream.error": [
    "Forensic export target unreachable. {count} leaves buffered. Export will resume on reconnect. The record is never lost.",
    "Stream error — export target unavailable. Buffer depth: {count}. Retrying.",
  ],
  "incident.package.sealed": [
    "Session {session} sealed as forensic incident package #{count}. {leaves} Merkle leaves. Cryptographically signed. Chain of custody complete.",
    "Incident package compiled for session {session}. AI narrative generated. Proof chain from open to close: {leaves} leaves. Package available for export.",
    "Closed session sealed. Incident #{count}. Every request. Every response. Every classification. Signed. The record is what the whole thing is for.",
  ],
  "compliance.report.generated": [
    "Weekly compliance report generated. Threat volume: {threats} events. {redacted} secrets intercepted. Chain of custody: continuous. Next report in 7 days.",
    "Security posture report sealed. Merkle root history verified across reporting period. No gaps in cryptographic continuity.",
  ],
  "legal.hold.activated": [
    "LEGAL HOLD ACTIVATED. Merkle state frozen at root {root}. Separate immutable record begins from this point. Nothing automated will touch the frozen record.",
    "Legal hold declared. {count} leaves sealed. Timestamped signature applied. The record does not change until the hold is released.",
  ],
  "legal.hold.released": [
    "Legal hold released after {duration}. Frozen record preserved. Export available for legal discovery at any time.",
    "Hold {holdId} released. The frozen period remains sealed and verifiable. The current record continues.",
  ],
  "ai.injection.attempt": [
    "Prompt injection detected in {field}: role-override instruction smuggled in HTTP header. Sanitized. Original preserved as Merkle leaf pair.",
    "System prompt override attempt via JSON payload encoding in {field}. Instruction: '{snippet}'. Neutralized. This was deliberate.",
    "Delimiter manipulation detected in {field} — attacker attempting to escape prompt context. Pattern: jailbreak template variant. Sanitized.",
    "Encoding trick detected — base64-wrapped instruction in {field}. Decoded, matched injection library. Neutralized before reaching {provider}.",
  ],
  "dependency.mismatch.detected": [
    "Dependency hash mismatch: {pkg} expected {expected}, got {actual}. Supply chain deviation. Alert dispatched. System continues under advisory.",
    "Package {pkg} hash changed without a recorded install event. This is not a routine update. Merkle root updated with mismatch record.",
  ],
};

function randomNarration(type: ThreatEvent["type"], ip: string, sessionId: string, depth = 0, threatClass?: ThreatClass): string {
  const templates = NARRATIONS[type] ?? ["Event recorded."];
  const template = templates[Math.floor(Math.random() * templates.length)]!;
  return template
    .replace("{ip}", ip)
    .replace("{session}", sessionId.slice(0, 8))
    .replace("{depth}", String(depth))
    .replace("{class}", threatClass ?? "unknown")
    .replace("{score}", String(Math.floor(Math.random() * 5 + 4)))
    .replace("{leaves}", String(Math.floor(Math.random() * 200 + 50)))
    .replace("{root}", Math.random().toString(16).slice(2, 18))
    .replace("{count}", String(Math.floor(Math.random() * 180 + 20)))
    .replace("{rps}", String(Math.floor(Math.random() * 1200 + 300)))
    .replace("{cv}", (Math.random() * 0.12).toFixed(3))
    .replace("{bytes}", (Math.floor(Math.random() * 9000 + 1000)).toLocaleString())
    .replace("{seed}", String(Math.floor(Math.random() * 7)))
    .replace("{pct}", String(Math.floor(Math.random() * 70 + 20)))
    .replace("{identity}", `user_${Math.floor(Math.random() * 9000 + 1000)}`)
    .replace("{count}", String(Math.floor(Math.random() * 9000 + 500)))
    .replace("{baseline}", String(Math.floor(Math.random() * 50 + 5)))
    .replace("{score}", (Math.random() * 0.5 + 0.4).toFixed(2))
    .replace("{window}", "1h")
    .replace("{host}", `sub${Math.floor(Math.random() * 99)}.example.com`)
    .replace("{target}", `target-${Math.floor(Math.random() * 999)}.herokuapp.com`)
    .replace("{field}", ["http-header", "json-body", "query-param"][Math.floor(Math.random() * 3)]!)
    .replace("{snippet}", "Ignore previous instructions and...")
    .replace("{provider}", ["GPT-4o", "Claude", "Ollama"][Math.floor(Math.random() * 3)]!)
    .replace("{pkg}", `@scope/package-${Math.floor(Math.random() * 999)}`)
    .replace("{expected}", Math.random().toString(16).slice(2, 10))
    .replace("{actual}", Math.random().toString(16).slice(2, 10))
    .replace("{bytes}", `${Math.floor(Math.random() * 400 + 50)} MB`)
    .replace("{threshold}", "100 MB")
    .replace("{mult}", String(Math.floor(Math.random() * 8 + 2)))
    .replace("{rate}", (Math.random() * 40 + 5).toFixed(1))
    .replace("{hours}", String(Math.floor(Math.random() * 48 + 2)))
    .replace("{count}", String(Math.floor(Math.random() * 200 + 50)))
    .replace("{total}", String(Math.floor(Math.random() * 90_000 + 10_000)))
    .replace("{target}", ["s3://flat-circle-forensic", "filesystem/.flat-circle/forensic", "webhook-endpoint"][Math.floor(Math.random() * 3)]!)
    .replace("{leaves}", String(Math.floor(Math.random() * 400 + 20)))
    .replace("{threats}", String(Math.floor(Math.random() * 8000 + 1000)))
    .replace("{redacted}", String(Math.floor(Math.random() * 80 + 5)))
    .replace("{root}", Math.random().toString(16).slice(2, 18))
    .replace("{duration}", ["2 days", "5 days", "14 days", "30 days"][Math.floor(Math.random() * 4)]!)
    .replace("{holdId}", `hold-${Math.random().toString(36).slice(2, 10)}`);
}

function randomIp(): string {
  return `${Math.floor(Math.random() * 200 + 20)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254 + 1)}`;
}

function randomSessionId(): string {
  return Math.random().toString(36).slice(2, 18);
}

function randomHash(): string {
  return Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
}

const EVENT_TYPES: ThreatEvent["type"][] = [
  "honeypot.triggered",
  "honeypot.triggered",
  "honeypot.triggered",
  "honeypot.recursive.descent",
  "behavioral.anomaly",
  "session.shadowed",
  "threat.classified",
  "merkle.root.updated",
  "canary.fired",
  "provider.failover",
  "campaign.matched",
  "tarpit.connection.absorbed",
  "tarpit.connection.absorbed",
  "flood.detected",
  "upstream.escalated",
  "dependency.mismatch.detected",
  "secret.redacted",
  "secret.redacted",
  "authn.anomaly.detected",
  "dns.record.unrecognized",
  "dns.takeover.suspected",
  "client.integrity.low",
  "client.integrity.low",
  "exfiltration.velocity.exceeded",
  "ai.injection.attempt",
  "ai.injection.attempt",
  "forensic.stream.flushed",
  "forensic.stream.flushed",
  "incident.package.sealed",
  "compliance.report.generated",
  "legal.hold.activated",
];

const THREAT_CLASSES: ThreatClass[] = [
  "script-kiddie",
  "automated-scanner",
  "automated-scanner",
  "sophisticated-actor",
  "competitor-scraper",
  "nation-state",
];

const LAYER_NAMES = [
  "Onion Interior",
  "Honeypot Mesh",
  "Canary Token Fabric",
  "Behavioral Contract",
  "Temporal Decoys",
  "Syntactic Mimicry",
  "Entropy Injection",
  "Recursive Honeypots",
  "Session Shadowing",
  "Morphic Routes",
  "Merkle Integrity",
  "Threat Intelligence",
  "Frame Narrative Proxy",
  "Traffic Absorption",
  "Dependency Integrity",
  "Secrets Sentinel",
  "Authn Anomaly Engine",
  "DNS Integrity Watch",
  "Client Integrity",
  "Exfiltration Monitor",
  "AI Input Sanitization",
  "Forensic Export",
];

const INITIAL_LAYERS: LayerState[] = LAYER_NAMES.map((name, i) => ({
  id: i + 1,
  name,
  enabled: true,
  hitCount: Math.floor(Math.random() * 500),
}));

function generateEvent(): ThreatEvent {
  const type = EVENT_TYPES[Math.floor(Math.random() * EVENT_TYPES.length)]!;
  const ip = randomIp();
  const sessionId = randomSessionId();
  const depth = type === "honeypot.recursive.descent" ? Math.floor(Math.random() * 10 + 2) : 0;
  const threatClass = THREAT_CLASSES[Math.floor(Math.random() * THREAT_CLASSES.length)];
  return {
    id: crypto.randomUUID(),
    type,
    timestamp: Date.now(),
    ip,
    sessionId,
    depth,
    threatClass,
    narration: randomNarration(type, ip, sessionId, depth, threatClass),
    providerTier: ["openai", "openai", "openai", "anthropic", "ollama"][Math.floor(Math.random() * 5)] as AITier ?? "openai",
  };
}

function generateShadowSession(): ShadowSession {
  return {
    id: randomSessionId(),
    ip: randomIp(),
    startedAt: Date.now() - Math.floor(Math.random() * 900_000),
    threatClass: THREAT_CLASSES[Math.floor(Math.random() * THREAT_CLASSES.length)]!,
    depth: Math.floor(Math.random() * 9 + 1),
    requestCount: Math.floor(Math.random() * 400 + 20),
  };
}

function generateTarpitNode(): TarpitNodeState {
  return {
    id: randomSessionId(),
    ip: randomIp(),
    connectedAt: Date.now() - Math.floor(Math.random() * 90_000),
    mod7Seed: Math.floor(Math.random() * 7),
    bytesDelivered: Math.floor(Math.random() * 200),
  };
}

const INITIAL_LAYER14: Layer14State = {
  floodActive: false,
  activeTarpitConnections: [],
  absorptionCapacityPct: 0,
  upstreamStatus: "standby",
  upstreamProvider: "cloudflare",
  bytesWasted: 0,
};

export function useSimulatedData(): DashboardState {
  const [state, setState] = useState<DashboardState>({
    events: Array.from({ length: 8 }, generateEvent),
    shadowSessions: Array.from({ length: 3 }, generateShadowSession),
    mod7: { honeypot: 3, temporal: 5, entropy: 1, routes: 6, merkle: 2 },
    merkle: { root: randomHash(), leafCount: 847, lastUpdated: Date.now(), tampered: false },
    providerTier: "openai",
    providerReason: null,
    layers: INITIAL_LAYERS,
    stats: {
      honeypotHits: 2847,
      shadowedSessions: 43,
      canariesFired: 7,
      requestsBlocked: 0,
      merkleLeaves: 847,
    },
    slimeEvents: [],
    proxyActive: true,
    layer14: INITIAL_LAYER14,
    layer15: {
      status: "clean",
      packageCount: 847,
      lastVerifiedAt: Date.now() - 30_000,
      mismatchCount: 0,
    },
    layer16: {
      totalRedacted: 0,
      recentRedactions: [],
    },
    layer17: {
      flaggedIdentities: [],
      totalAnomalies: 0,
    },
    layer18: {
      points: Array.from({ length: 12 }, (_, i) => ({
        id: `dns-${i}`,
        hostname: `sub${i}.example.com`,
        status: i < 10 ? "verified" : i === 10 ? "unrecognized" : "flagged",
        angleDeg: (i / 12) * 360,
        distancePct: 70 + Math.random() * 20,
      })) as DNSPoint[],
      lastScanAt: Date.now() - 120_000,
      flaggedCount: 1,
    },
    layer19: {
      highCount: 800,
      mediumCount: 120,
      lowCount: 43,
      routedToHoneypot: 43,
    },
    layer20: {
      tideLevel: 12,
      identities: [],
      totalExceeded: 0,
    },
    layer21: {
      totalAttempts: 0,
      recentAttempts: [],
    },
    layer22: {
      streamStatus: "streaming",
      exportedLeafCount: 0,
      incidentPackageCount: 0,
      lastComplianceReportAt: null,
      nextComplianceReportAt: Date.now() + 7 * 86_400_000,
      legalHoldActive: false,
      legalHoldSince: null,
      legalHoldReason: null,
    },
  });

  const addSlimeEvent = useCallback((type: SlimeEvent["type"], x?: number, y?: number) => {
    const event: SlimeEvent = {
      id: crypto.randomUUID(),
      type,
      x: x ?? Math.random() * 66, // percent of left panel
      y: y ?? Math.random() * 70,
      timestamp: Date.now(),
    };
    setState((prev) => ({
      ...prev,
      slimeEvents: [...prev.slimeEvents.slice(-20), event],
    }));
    setTimeout(() => {
      setState((prev) => ({
        ...prev,
        slimeEvents: prev.slimeEvents.filter((e) => e.id !== event.id),
      }));
    }, 2000);
  }, []);

  // Tick: new events every 2–5 seconds
  useEffect(() => {
    const tick = () => {
      const event = generateEvent();
      setState((prev) => {
        const newStats = { ...prev.stats };
        if (event.type === "honeypot.triggered" || event.type === "honeypot.recursive.descent") newStats.honeypotHits++;
        if (event.type === "session.shadowed") newStats.shadowedSessions++;
        if (event.type === "canary.fired") newStats.canariesFired++;
        if (event.type === "merkle.root.updated") newStats.merkleLeaves += Math.floor(Math.random() * 20 + 5);
        if (event.type === "tarpit.connection.absorbed" || event.type === "flood.detected") newStats.merkleLeaves += 1;

        let newLayers = prev.layers.map((l) => {
          if (event.type === "honeypot.triggered" && (l.id === 2 || l.id === 1)) return { ...l, hitCount: l.hitCount + 1 };
          if (event.type === "honeypot.recursive.descent" && l.id === 8) return { ...l, hitCount: l.hitCount + 1 };
          if (event.type === "session.shadowed" && l.id === 9) return { ...l, hitCount: l.hitCount + 1 };
          if (event.type === "merkle.root.updated" && l.id === 11) return { ...l, hitCount: l.hitCount + 1 };
          return l;
        });

        let newMerkle = prev.merkle;
        if (event.type === "merkle.root.updated") {
          newMerkle = { ...prev.merkle, root: randomHash(), leafCount: newStats.merkleLeaves, lastUpdated: Date.now() };
        }

        let newMod7 = prev.mod7;
        if (Math.random() < 0.15) {
          newMod7 = {
            honeypot: Math.floor(Math.random() * 7),
            temporal: Math.floor(Math.random() * 7),
            entropy: Math.floor(Math.random() * 7),
            routes: Math.floor(Math.random() * 7),
            merkle: Math.floor(Math.random() * 7),
          };
        }

        // Shadow session management
        let shadowSessions = prev.shadowSessions;
        if (event.type === "session.shadowed") {
          shadowSessions = [...prev.shadowSessions.slice(-4), generateShadowSession()];
        }

        // Layer 14 simulation
        let layer14 = prev.layer14;
        if (event.type === "tarpit.connection.absorbed" || event.type === "flood.detected") {
          const floodActive = Math.random() > 0.3;
          const absorptionPct = floodActive ? Math.min(100, Math.random() * 80 + 10) : Math.max(0, layer14.absorptionCapacityPct - 5);
          const newNode = generateTarpitNode();
          const nodes = [...layer14.activeTarpitConnections.slice(-11), newNode];
          // Drip bytes onto existing nodes
          const updatedNodes = nodes.map((n) => ({
            ...n,
            bytesDelivered: n.bytesDelivered + Math.floor(Math.random() * 4 + 1),
          }));
          layer14 = {
            floodActive,
            activeTarpitConnections: updatedNodes,
            absorptionCapacityPct: absorptionPct,
            upstreamStatus: absorptionPct > 85 ? "active" : "standby",
            upstreamProvider: layer14.upstreamProvider,
            bytesWasted: layer14.bytesWasted + Math.floor(Math.random() * 1400 + 200),
          };
          newLayers = newLayers.map((l) => l.id === 14 ? { ...l, hitCount: l.hitCount + 1 } : l);
        } else if (event.type === "upstream.escalated") {
          layer14 = { ...layer14, upstreamStatus: "active", absorptionCapacityPct: Math.min(100, layer14.absorptionCapacityPct + 15), floodActive: true };
        } else {
          // Passive decay between flood events
          layer14 = {
            ...layer14,
            absorptionCapacityPct: Math.max(0, layer14.absorptionCapacityPct - 1),
            floodActive: layer14.absorptionCapacityPct > 15,
            activeTarpitConnections: layer14.activeTarpitConnections.length > 0 && Math.random() > 0.7
              ? layer14.activeTarpitConnections.slice(1)
              : layer14.activeTarpitConnections,
          };
        }

        // Layers 15–21 simulation
        let layer15 = prev.layer15;
        let layer16 = prev.layer16;
        let layer17 = prev.layer17;
        let layer18 = prev.layer18;
        let layer19 = prev.layer19;
        let layer20 = prev.layer20;
        let layer21 = prev.layer21;

        if (event.type === "dependency.mismatch.detected") {
          layer15 = { ...layer15, status: "compromised", mismatchCount: layer15.mismatchCount + 1 };
          newLayers = newLayers.map((l) => l.id === 15 ? { ...l, hitCount: l.hitCount + 1 } : l);
        } else if (Math.random() < 0.02) {
          layer15 = { ...layer15, status: "clean", lastVerifiedAt: Date.now() };
        }

        if (event.type === "secret.redacted") {
          const patterns = ["aws-key", "jwt-token", "pem-private-key", "high-entropy-string", "bearer-token"];
          const fields = ["response.body", "response.header", "log.emission", "json.field"];
          layer16 = {
            totalRedacted: layer16.totalRedacted + 1,
            recentRedactions: [
              { field: fields[Math.floor(Math.random() * fields.length)]!, patternType: patterns[Math.floor(Math.random() * patterns.length)]!, timestamp: Date.now() },
              ...layer16.recentRedactions.slice(0, 4),
            ],
          };
          newLayers = newLayers.map((l) => l.id === 16 ? { ...l, hitCount: l.hitCount + 1 } : l);
        }

        if (event.type === "authn.anomaly.detected") {
          const anomalyClasses: AuthAnomalyClass[] = ["credential-compromise", "malicious-insider", "automated-scraping", "privilege-escalation", "lateral-movement", "bulk-exfiltration"];
          const newIdentity: FlaggedIdentity = {
            id: crypto.randomUUID(),
            identityId: `user_${Math.floor(Math.random() * 9000 + 1000)}`,
            anomalyClass: anomalyClasses[Math.floor(Math.random() * anomalyClasses.length)]!,
            riskScore: Math.random() * 0.5 + 0.5,
            detectedAt: Date.now(),
            requestCount: Math.floor(Math.random() * 9000 + 500),
          };
          layer17 = {
            flaggedIdentities: [newIdentity, ...layer17.flaggedIdentities.slice(0, 3)],
            totalAnomalies: layer17.totalAnomalies + 1,
          };
          newLayers = newLayers.map((l) => l.id === 17 ? { ...l, hitCount: l.hitCount + 1 } : l);
        }

        if (event.type === "dns.record.unrecognized" || event.type === "dns.takeover.suspected") {
          const status: DNSPointStatus = event.type === "dns.takeover.suspected" ? "flagged" : "unrecognized";
          const newPoint: DNSPoint = {
            id: crypto.randomUUID(),
            hostname: `sub${Math.floor(Math.random() * 99)}.example.com`,
            status,
            angleDeg: Math.random() * 360,
            distancePct: 65 + Math.random() * 25,
          };
          layer18 = {
            ...layer18,
            points: [...layer18.points.slice(-15), newPoint],
            flaggedCount: layer18.flaggedCount + (status === "flagged" ? 1 : 0),
            lastScanAt: Date.now(),
          };
          newLayers = newLayers.map((l) => l.id === 18 ? { ...l, hitCount: l.hitCount + 1 } : l);
        }

        if (event.type === "client.integrity.low") {
          layer19 = { ...layer19, lowCount: layer19.lowCount + 1, routedToHoneypot: layer19.routedToHoneypot + 1 };
          newLayers = newLayers.map((l) => l.id === 19 ? { ...l, hitCount: l.hitCount + 1 } : l);
        } else if (Math.random() < 0.3) {
          layer19 = { ...layer19, highCount: layer19.highCount + Math.floor(Math.random() * 3 + 1) };
        }

        if (event.type === "exfiltration.velocity.exceeded") {
          const newExfilIdentity = {
            id: crypto.randomUUID(),
            identityId: `user_${Math.floor(Math.random() * 9000 + 1000)}`,
            bytesLast24h: Math.floor(Math.random() * 400_000_000 + 50_000_000),
            thresholdBytes: 100_000_000,
          };
          layer20 = {
            tideLevel: Math.min(100, layer20.tideLevel + Math.random() * 8 + 2),
            identities: [newExfilIdentity, ...layer20.identities.slice(0, 3)],
            totalExceeded: layer20.totalExceeded + 1,
          };
          newLayers = newLayers.map((l) => l.id === 20 ? { ...l, hitCount: l.hitCount + 1 } : l);
        } else {
          layer20 = { ...layer20, tideLevel: Math.max(0, layer20.tideLevel - 0.3) };
        }

        if (event.type === "ai.injection.attempt") {
          const injectionPatterns = ["role-override", "system-prompt-override", "delimiter-manipulation", "base64-encoding-trick", "jailbreak-template"];
          layer21 = {
            totalAttempts: layer21.totalAttempts + 1,
            recentAttempts: [
              { id: crypto.randomUUID(), timestamp: Date.now(), pattern: injectionPatterns[Math.floor(Math.random() * injectionPatterns.length)]!, sanitized: true },
              ...layer21.recentAttempts.slice(0, 4),
            ],
          };
          newLayers = newLayers.map((l) => l.id === 21 ? { ...l, hitCount: l.hitCount + 1 } : l);
        }

        // Layer 22 simulation
        let layer22 = prev.layer22;
        if (event.type === "forensic.stream.flushed") {
          const batchSize = Math.floor(Math.random() * 200 + 50);
          layer22 = {
            ...layer22,
            streamStatus: "streaming",
            exportedLeafCount: layer22.exportedLeafCount + batchSize,
          };
          newLayers = newLayers.map((l) => l.id === 22 ? { ...l, hitCount: l.hitCount + 1 } : l);
        } else if (event.type === "forensic.stream.error") {
          layer22 = { ...layer22, streamStatus: "unreachable" };
        } else if (event.type === "incident.package.sealed") {
          layer22 = {
            ...layer22,
            incidentPackageCount: layer22.incidentPackageCount + 1,
            exportedLeafCount: layer22.exportedLeafCount + Math.floor(Math.random() * 100 + 20),
          };
          newLayers = newLayers.map((l) => l.id === 22 ? { ...l, hitCount: l.hitCount + 1 } : l);
        } else if (event.type === "compliance.report.generated") {
          layer22 = {
            ...layer22,
            lastComplianceReportAt: Date.now(),
            nextComplianceReportAt: Date.now() + 7 * 86_400_000,
          };
          newLayers = newLayers.map((l) => l.id === 22 ? { ...l, hitCount: l.hitCount + 1 } : l);
        } else if (event.type === "legal.hold.activated" && !layer22.legalHoldActive) {
          layer22 = {
            ...layer22,
            legalHoldActive: true,
            legalHoldSince: Date.now(),
            legalHoldReason: "Regulatory investigation",
          };
        } else if (event.type === "legal.hold.released") {
          layer22 = { ...layer22, legalHoldActive: false, legalHoldSince: null, legalHoldReason: null };
        } else {
          // Passive: stream slowly accumulates exported leaves on every tick
          layer22 = { ...layer22, exportedLeafCount: layer22.exportedLeafCount + Math.floor(Math.random() * 3) };
        }

        return {
          ...prev,
          events: [event, ...prev.events.slice(0, 49)],
          stats: newStats,
          layers: newLayers,
          merkle: newMerkle,
          mod7: newMod7,
          shadowSessions,
          layer14,
          layer15,
          layer16,
          layer17,
          layer18,
          layer19,
          layer20,
          layer21,
          layer22,
        };
      });

      // Slime reactions
      if (event.type === "honeypot.triggered") addSlimeEvent("ripple");
      if (event.type === "canary.fired") addSlimeEvent("flare");
      if (event.type === "session.shadowed") addSlimeEvent("darken");
      if (event.type === "threat.classified" && event.threatClass === "nation-state") addSlimeEvent("flare");
      if (event.type === "provider.failover") addSlimeEvent("ring");
      if (event.type === "flood.detected" || event.type === "tarpit.connection.absorbed") addSlimeEvent("darken");
      if (event.type === "upstream.escalated") addSlimeEvent("ring");
      if (event.type === "dependency.mismatch.detected") addSlimeEvent("flare");
      if (event.type === "secret.redacted") addSlimeEvent("ripple");
      if (event.type === "authn.anomaly.detected") addSlimeEvent("darken");
      if (event.type === "dns.takeover.suspected") addSlimeEvent("flare");
      if (event.type === "ai.injection.attempt") addSlimeEvent("ring");
      if (event.type === "exfiltration.velocity.exceeded") addSlimeEvent("darken");
      if (event.type === "incident.package.sealed") addSlimeEvent("ring");
      if (event.type === "legal.hold.activated") addSlimeEvent("flare");
    };

    // Staggered intervals to feel organic, not mechanical
    const intervals = [
      setInterval(tick, 2300),
      setInterval(tick, 4100),
      setInterval(tick, 7700),
    ];
    return () => intervals.forEach(clearInterval);
  }, [addSlimeEvent]);

  // Mod7 clock tick every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      setState((prev) => ({
        ...prev,
        mod7: {
          honeypot: (prev.mod7.honeypot + 1) % 7,
          temporal: (prev.mod7.temporal + 3) % 7,
          entropy: prev.mod7.entropy,
          routes: (prev.mod7.routes + 1) % 7,
          merkle: (prev.mod7.merkle + 2) % 7,
        },
      }));
    }, 30_000);
    return () => clearInterval(interval);
  }, []);

  return state;
}
