import { useState, useEffect, useCallback } from "react";

export type AITier = "openai" | "anthropic" | "ollama" | "static";
export type ThreatClass = "script-kiddie" | "automated-scanner" | "sophisticated-actor" | "competitor-scraper" | "nation-state";

export interface ThreatEvent {
  id: string;
  type: "honeypot.triggered" | "honeypot.recursive.descent" | "canary.fired" | "behavioral.anomaly" | "session.shadowed" | "threat.classified" | "merkle.root.updated" | "provider.failover" | "campaign.matched";
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
}

export interface SlimeEvent {
  id: string;
  type: "ripple" | "flare" | "darken" | "ring";
  x: number;
  y: number;
  timestamp: number;
}

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
    .replace("{root}", Math.random().toString(16).slice(2, 18));
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

        const newLayers = prev.layers.map((l) => {
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

        return {
          ...prev,
          events: [event, ...prev.events.slice(0, 49)],
          stats: newStats,
          layers: newLayers,
          merkle: newMerkle,
          mod7: newMod7,
          shadowSessions,
        };
      });

      // Slime reactions
      if (event.type === "honeypot.triggered") addSlimeEvent("ripple");
      if (event.type === "canary.fired") addSlimeEvent("flare");
      if (event.type === "session.shadowed") addSlimeEvent("darken");
      if (event.type === "threat.classified" && event.threatClass === "nation-state") addSlimeEvent("flare");
      if (event.type === "provider.failover") addSlimeEvent("ring");
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
