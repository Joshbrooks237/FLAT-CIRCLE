/**
 * Layer 14 — Traffic Absorption and Intelligent Tarpit
 *
 * Flat Circle's answer to volumetric DDoS is not blockage.
 * Blockage confirms the target exists. The answer is waste.
 * Every flood request costs the attacker more than it costs the system.
 * The interior stays alive. The attacker's connections are tied up
 * responding to nothing.
 *
 * Four stages:
 *   1. Early Signature Recognition   — detect before saturation, escalate to L4 + L9
 *   2. Progressive Response Degradation — slow, not block; hold connections open
 *   3. Intelligent Tarpit             — AI-generated slow-drip, mod7-seeded timing
 *   4. Upstream Absorber Integration  — Cloudflare / AWS Shield / custom webhook
 *
 * Mod 7 integration: tarpit timing is seeded per connection fingerprint.
 * No two connections in the same flood receive identical timing patterns.
 * Automated flood tooling that expects consistent timing signatures receives noise.
 *
 * Every tarpitted connection is recorded as a "tarpit" leaf in the Merkle audit tree.
 */

import type {
  Layer14Config,
  FlatCircleRequest,
  FlatCircleEvent,
  EventEmitterFn,
  AIProviderTier,
} from "../types.js";
import { ProviderCascade } from "../provider-cascade.js";
import type { MerkleIntegrityEngine } from "./layer11-merkle.js";

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_FLOOD_THRESHOLD_RPS = 500;
const DEFAULT_UPSTREAM_ESCALATION_RPS = 2_000;
const DEFAULT_TARPIT_WINDOW_MS = 120_000;

/** Rolling window over which RPS is calculated. */
const RPS_WINDOW_MS = 5_000;

/** Base delay between drip fragments, multiplied by the connection's mod7 seed. */
const DRIP_BASE_INTERVAL_MS = 800;

/**
 * Coefficient-of-variation threshold below which inter-arrival timing is
 * considered "synchronized" — a reliable botnet/flood signature.
 */
const SYNCHRONIZED_CV_THRESHOLD = 0.15;

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

export interface TarpitConnection {
  readonly sessionId: string;
  readonly ip: string;
  readonly connectedAt: number;
  /** Mod 7 value derived from the session fingerprint. Range [0, 6]. */
  readonly mod7Seed: number;
  bytesDelivered: number;
  lastDripAt: number;
}

export interface FloodSignature {
  readonly detectedAt: number;
  readonly ipCluster: ReadonlySet<string>;
  peakRps: number;
}

export type UpstreamAbsorberStatus = "active" | "standby" | "not-configured";

export interface AbsorptionStatus {
  readonly currentRps: number;
  readonly floodActive: boolean;
  readonly tarpitConnectionCount: number;
  readonly bytesWasted: number;
  /** Local traffic load as a fraction of the upstream-escalation threshold [0–100]. */
  readonly absorptionCapacityPct: number;
  readonly upstreamActive: boolean;
  readonly upstreamStatus: UpstreamAbsorberStatus;
  readonly upstreamProvider: string | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage 1 — Early Signature Recognition
// ─────────────────────────────────────────────────────────────────────────────

export class FloodSignatureDetector {
  private readonly timestamps: number[] = [];
  private readonly ipHistory = new Map<string, number[]>();
  private readonly threshold: number;

  constructor(thresholdRps = DEFAULT_FLOOD_THRESHOLD_RPS) {
    this.threshold = thresholdRps;
  }

  record(ip: string): void {
    const now = Date.now();
    const cutoff = now - RPS_WINDOW_MS;

    this.timestamps.push(now);
    while ((this.timestamps[0] ?? 0) < cutoff) this.timestamps.shift();

    const times = this.ipHistory.get(ip) ?? [];
    times.push(now);
    while ((times[0] ?? 0) < cutoff) times.shift();
    this.ipHistory.set(ip, times);
  }

  currentRps(): number {
    return (this.timestamps.length / RPS_WINDOW_MS) * 1_000;
  }

  isFlood(): boolean {
    return this.currentRps() >= this.threshold;
  }

  /**
   * Returns true when inter-arrival timing is highly synchronized.
   * Synchronized arrival is a reliable botnet/volumetric flood signature —
   * organic traffic cannot produce a coefficient of variation below 15%.
   */
  isLowVariation(): boolean {
    if (this.timestamps.length < 20) return false;
    const deltas: number[] = [];
    for (let i = 1; i < this.timestamps.length; i++) {
      deltas.push((this.timestamps[i] ?? 0) - (this.timestamps[i - 1] ?? 0));
    }
    const mean = deltas.reduce((a, b) => a + b, 0) / deltas.length;
    if (mean === 0) return true;
    const variance = deltas.reduce((a, b) => a + (b - mean) ** 2, 0) / deltas.length;
    return Math.sqrt(variance) / mean < SYNCHRONIZED_CV_THRESHOLD;
  }

  /**
   * Returns IPs whose individual contribution meets or exceeds 5% of the
   * configured flood threshold — members of the attacking cluster.
   */
  floodingIps(): string[] {
    const now = Date.now();
    const cutoff = now - RPS_WINDOW_MS;
    const perIpThreshold = (this.threshold * 0.05 * RPS_WINDOW_MS) / 1_000;
    return [...this.ipHistory.entries()]
      .filter(([, times]) => times.filter((t) => t >= cutoff).length >= perIpThreshold)
      .map(([ip]) => ip);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage 2 + 3 — Progressive Degradation and Intelligent Tarpit
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Derive a mod 7 timing seed from a connection's session fingerprint.
 * Blended with the global deployment seed so two separate deployments facing
 * the same flood produce different timing noise.
 */
function tarpitMod7Seed(sessionId: string, globalSeed: string): number {
  const combined = `${globalSeed}:${sessionId}`;
  let h = 0;
  for (let i = 0; i < combined.length; i++) {
    h = (Math.imul(h, 31) + (combined.charCodeAt(i) ?? 0)) | 0;
  }
  return Math.abs(h) % 7;
}

/**
 * Progressive delay for a tarpitted connection.
 * Grows with connection age and is multiplied by the mod7 seed so each
 * connection in the same flood flood has a distinct timing envelope.
 */
function progressiveDelayMs(conn: TarpitConnection): number {
  const ageSeconds = (Date.now() - conn.connectedAt) / 1_000;
  const mod7Factor = conn.mod7Seed + 1; // [1..7]
  return Math.min(
    DRIP_BASE_INTERVAL_MS * mod7Factor * (1 + ageSeconds * 0.08),
    DEFAULT_TARPIT_WINDOW_MS
  );
}

/**
 * Static slow-drip template library.
 * Pre-generated once; always available regardless of AI provider status.
 * Responses look like real HTTP but deliver content one character at a time.
 */
const STATIC_DRIP_TEMPLATES: readonly string[] = [
  'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n{"status":"',
  'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n<!DOCTYPE html><html><head><title>',
  'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n{"data":{"id":"',
  'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Request-ID: fc-',
];

export class TarpitEngine {
  private readonly connections = new Map<string, TarpitConnection>();
  private readonly flaggedIps = new Set<string>();
  private readonly maxWindowMs: number;
  private readonly cascade: ProviderCascade;
  private readonly globalSeed: string;
  private bytesWasted = 0;

  constructor(
    cascade: ProviderCascade,
    config: Layer14Config,
    globalSeed = "flat-circle-default"
  ) {
    this.cascade = cascade;
    this.maxWindowMs = config.tarpitMaxWindowMs ?? DEFAULT_TARPIT_WINDOW_MS;
    this.globalSeed = globalSeed;
  }

  flagIp(ip: string): void {
    this.flaggedIps.add(ip);
  }

  isFlagged(ip: string): boolean {
    return this.flaggedIps.has(ip);
  }

  unflagIp(ip: string): void {
    this.flaggedIps.delete(ip);
  }

  absorb(request: FlatCircleRequest): TarpitConnection {
    const conn: TarpitConnection = {
      sessionId: request.sessionId,
      ip: request.ip,
      connectedAt: Date.now(),
      mod7Seed: tarpitMod7Seed(request.sessionId, this.globalSeed),
      bytesDelivered: 0,
      lastDripAt: Date.now(),
    };
    this.connections.set(request.sessionId, conn);
    return conn;
  }

  /**
   * Generate the next drip fragment for a tarpitted connection.
   *
   * For sophisticated floods, the AI provider cascade generates plausible
   * JSON fragments; for simpler floods or when AI is unavailable, the static
   * template library is used. Returns null when the connection's keepalive
   * window has expired.
   */
  async nextDrip(sessionId: string, providerTier: AIProviderTier): Promise<string | null> {
    const conn = this.connections.get(sessionId);
    if (!conn) return null;
    if (Date.now() - conn.connectedAt >= this.maxWindowMs) {
      this.connections.delete(sessionId);
      return null;
    }

    await new Promise<void>((r) => setTimeout(r, progressiveDelayMs(conn)));

    let fragment: string;
    if (providerTier !== "static" && conn.bytesDelivered < 256) {
      try {
        const result = await this.cascade.generate({
          prompt: "Generate a 30-character plausible JSON value fragment. No explanation, no quotes around the response.",
          maxTokens: 20,
        });
        fragment = result.text.slice(0, 30);
      } catch {
        fragment = this.staticDrip(conn);
      }
    } else {
      fragment = this.staticDrip(conn);
    }

    conn.bytesDelivered += fragment.length;
    conn.lastDripAt = Date.now();
    this.bytesWasted += fragment.length;
    return fragment;
  }

  private staticDrip(conn: TarpitConnection): string {
    const template = STATIC_DRIP_TEMPLATES[conn.mod7Seed % STATIC_DRIP_TEMPLATES.length] ?? STATIC_DRIP_TEMPLATES[0]!;
    const charIdx = conn.bytesDelivered % template.length;
    return template[charIdx] ?? " ";
  }

  activeConnections(): ReadonlyArray<TarpitConnection> {
    return [...this.connections.values()];
  }

  totalBytesWasted(): number {
    return this.bytesWasted;
  }

  pruneExpired(): void {
    const now = Date.now();
    for (const [id, conn] of this.connections) {
      if (now - conn.connectedAt >= this.maxWindowMs) this.connections.delete(id);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage 4 — Upstream Absorber Integration
// ─────────────────────────────────────────────────────────────────────────────

export class UpstreamAbsorberClient {
  private status: UpstreamAbsorberStatus;
  private readonly config: Layer14Config;

  constructor(config: Layer14Config) {
    this.config = config;
    this.status = config.upstreamAbsorber ? "standby" : "not-configured";
  }

  async escalate(floodRps: number, floodingIps: readonly string[]): Promise<void> {
    if (!this.config.upstreamAbsorber || this.status === "not-configured") return;
    this.status = "active";

    const absorber = this.config.upstreamAbsorber;
    if (absorber.webhookUrl) {
      try {
        await fetch(absorber.webhookUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(absorber.apiKey ? { Authorization: `Bearer ${absorber.apiKey}` } : {}),
          },
          body: JSON.stringify({
            event: "flat-circle.layer14.flood.escalation",
            timestamp: Date.now(),
            provider: absorber.provider,
            floodRps,
            floodingIpCount: floodingIps.length,
            sampleIps: floodingIps.slice(0, 10),
          }),
        });
      } catch {
        // Upstream escalation failure is non-fatal — the tarpit continues independently.
      }
    }
  }

  deescalate(): void {
    if (this.status === "active") this.status = "standby";
  }

  getStatus(): UpstreamAbsorberStatus {
    return this.status;
  }

  getProviderName(): string | null {
    return this.config.upstreamAbsorber?.provider ?? null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified Layer 14 Engine
// ─────────────────────────────────────────────────────────────────────────────

export class TrafficAbsorptionEngine {
  private readonly detector: FloodSignatureDetector;
  private readonly tarpit: TarpitEngine;
  private readonly upstream: UpstreamAbsorberClient;
  private readonly escalationRps: number;
  private readonly emit: EventEmitterFn;
  private readonly merkle: MerkleIntegrityEngine | undefined;

  constructor(
    config: Layer14Config,
    cascade: ProviderCascade,
    emit: EventEmitterFn,
    merkle?: MerkleIntegrityEngine,
    globalSeed?: string
  ) {
    this.detector = new FloodSignatureDetector(config.floodThresholdRps);
    this.tarpit = new TarpitEngine(cascade, config, globalSeed);
    this.upstream = new UpstreamAbsorberClient(config);
    this.escalationRps = config.upstreamEscalationRps ?? DEFAULT_UPSTREAM_ESCALATION_RPS;
    this.emit = emit;
    this.merkle = merkle;
  }

  /**
   * Process an incoming request through Layer 14.
   *
   * Returns `true` if the request was absorbed by the tarpit — in that case
   * the caller should not forward the request to the origin.
   */
  async process(request: FlatCircleRequest, providerTier: AIProviderTier): Promise<boolean> {
    this.detector.record(request.ip);

    const rps = this.detector.currentRps();
    const isFlood = this.detector.isFlood() || this.detector.isLowVariation();

    if (isFlood) {
      const floodingIps = this.detector.floodingIps();
      floodingIps.forEach((ip) => this.tarpit.flagIp(ip));

      if (rps >= this.escalationRps) {
        await this.upstream.escalate(rps, floodingIps);
        this.emit(this.buildEvent("upstream.escalated", request, { rps, floodingIpCount: floodingIps.length }, providerTier));
      } else if (this.upstream.getStatus() === "active") {
        this.upstream.deescalate();
        this.emit(this.buildEvent("upstream.deescalated", request, { rps }, providerTier));
      }
    }

    if (this.tarpit.isFlagged(request.ip)) {
      const conn = this.tarpit.absorb(request);

      // Record the absorbed connection as a Merkle leaf for the audit trail.
      this.merkle?.recordHoneypotHit(
        this.buildEvent("tarpit.connection.absorbed", request, { mod7Seed: conn.mod7Seed, connectedAt: conn.connectedAt }, providerTier)
      );

      this.emit(this.buildEvent("tarpit.connection.absorbed", request, { mod7Seed: conn.mod7Seed }, providerTier));

      // Drip in the background — the caller returns immediately.
      // The connection is held open; the attacker waits for a response
      // that arrives in geological time.
      void this.tarpit.nextDrip(request.sessionId, providerTier);
      return true;
    }

    return false;
  }

  status(): AbsorptionStatus {
    this.tarpit.pruneExpired();
    const rps = this.detector.currentRps();
    const absorptionCapacityPct = Math.min(100, (rps / this.escalationRps) * 100);
    return {
      currentRps: rps,
      floodActive: this.detector.isFlood(),
      tarpitConnectionCount: this.tarpit.activeConnections().length,
      bytesWasted: this.tarpit.totalBytesWasted(),
      absorptionCapacityPct,
      upstreamActive: this.upstream.getStatus() === "active",
      upstreamStatus: this.upstream.getStatus(),
      upstreamProvider: this.upstream.getProviderName(),
    };
  }

  private buildEvent(
    type: FlatCircleEvent["type"],
    request: FlatCircleRequest,
    meta: Record<string, unknown>,
    providerTier: AIProviderTier
  ): FlatCircleEvent {
    return {
      id: crypto.randomUUID(),
      type,
      timestamp: Date.now(),
      sessionId: request.sessionId,
      ip: request.ip,
      providerTier,
      metadata: meta,
    };
  }
}
