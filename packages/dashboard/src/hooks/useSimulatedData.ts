import { useState, useEffect, useCallback } from "react";

export type AITier = "openai" | "anthropic" | "ollama" | "static";
export type ThreatClass = "script-kiddie" | "automated-scanner" | "sophisticated-actor" | "competitor-scraper" | "nation-state";

export interface ThreatEvent {
  id: string;
  type: "honeypot.triggered" | "honeypot.recursive.descent" | "canary.fired" | "behavioral.anomaly" | "session.shadowed" | "threat.classified" | "merkle.root.updated" | "provider.failover" | "campaign.matched" | "tarpit.connection.absorbed" | "flood.detected" | "upstream.escalated";
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
    .replace("{pct}", String(Math.floor(Math.random() * 70 + 20)));
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

        return {
          ...prev,
          events: [event, ...prev.events.slice(0, 49)],
          stats: newStats,
          layers: newLayers,
          merkle: newMerkle,
          mod7: newMod7,
          shadowSessions,
          layer14,
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
