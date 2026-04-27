/**
 * Layer 19 — Client Integrity Verification
 *
 * Behavioral contracts detect what a client does. Layer 19 detects what a
 * client is.
 *
 * Real browsers have a measurable fingerprint at the TLS and HTTP layer that
 * headless browsers, automated scanners, and bot frameworks cannot fully
 * replicate. JA3 TLS fingerprints identify the underlying TLS client library.
 * HTTP/2 fingerprinting catches clients that claim to be browsers but
 * negotiate the protocol differently.
 *
 * Low-integrity clients are not blocked — they are routed to the honeypot
 * mesh (Layer 2) with enhanced AI-generated responses calibrated to what
 * an automated tool expects to find.
 */

import type {
  Layer19Config,
  FlatCircleRequest,
  FlatCircleEvent,
  EventEmitterFn,
  AIProviderTier,
} from "../types.js";
import type { ProviderCascade } from "../provider-cascade.js";
import type { MerkleIntegrityEngine } from "./layer11-merkle.js";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface TLSFingerprint {
  /** JA3 hash of the client's TLS ClientHello */
  readonly ja3Hash: string;
  /** The TLS version negotiated */
  readonly version?: string;
  /** Cipher suites offered */
  readonly cipherSuites?: number[];
  /** Extensions present */
  readonly extensions?: number[];
}

export interface HTTP2Fingerprint {
  /** SETTINGS frame parameters as presented by the client */
  readonly settings?: Record<string, number>;
  /** Window size from WINDOW_UPDATE frame */
  readonly windowSize?: number;
  /** Pseudo-header order */
  readonly headerOrder?: string[];
}

export interface ClientIntegrityInput {
  readonly request: FlatCircleRequest;
  readonly tls?: TLSFingerprint;
  readonly http2?: HTTP2Fingerprint;
}

export interface ClientIntegrityScore {
  readonly score: number;  // [0, 1] — 1 = high integrity (real browser)
  readonly ja3Score: number;
  readonly http2Score: number;
  readonly uaConsistencyScore: number;
  readonly isLowIntegrity: boolean;
  readonly suspectedTool: string | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Known JA3 fingerprints
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A curated set of JA3 hashes known to belong to real browser builds.
 * This is not exhaustive — it is a high-confidence "known-good" set.
 * Unknown JA3s receive a penalty score but are not auto-failed.
 */
const KNOWN_BROWSER_JA3 = new Set([
  "cd08e31494f9531f560d64c695473da9", // Chrome 120 on macOS
  "b32309a26951912be7dba376398abc3b", // Chrome 119 on Windows
  "aa5b3afc36e3a78dfabbaab0b9bffde6", // Firefox 121 on macOS
  "3b5074b1b5d032e5620f69f9159a8945", // Safari 17 on macOS
  "6734f37431670b3ab4292b8f60f29984", // Edge 120 on Windows
]);

/**
 * JA3 hashes associated with known scanning/bot tools.
 */
const KNOWN_BOT_JA3 = new Map<string, string>([
  ["4d7a28d6f2263ed61de88ca66eb011e3", "python-requests"],
  ["3b5074b1b5d032e5620f69f9159a8945", "go-http"],
  ["a0e9f5d64349fb13191bc781f81f42e1", "curl"],
  ["c27f9b00f1edf3d2d9c4e12f9e9e33d9", "nuclei-scanner"],
  ["e7d705a3286e19ea42f587b344ee6865", "sqlmap"],
  ["6bea65232d8f69e2af3813e679d11b5b", "nikto"],
  ["19e29534fd49dd27d09234e639c4057e", "python-httpx"],
]);

// ─────────────────────────────────────────────────────────────────────────────
// HTTP/2 fingerprint comparison
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Expected SETTINGS values for real browser H2 fingerprints.
 * Deviations from these contribute to the bot score.
 */
const BROWSER_H2_SETTINGS: Record<string, [number, number]> = {
  HEADER_TABLE_SIZE:      [65536, 4096],
  INITIAL_WINDOW_SIZE:    [6291456, 65535],
  MAX_HEADER_LIST_SIZE:   [262144, 0],
  ENABLE_PUSH:            [0, 1],
};

function scoreHttp2Fingerprint(h2: HTTP2Fingerprint | undefined): number {
  if (!h2?.settings) return 0.5; // No H2 data — neutral
  let score = 1.0;
  for (const [key, [browserVal]] of Object.entries(BROWSER_H2_SETTINGS)) {
    const actual = h2.settings[key];
    if (actual !== undefined && actual !== browserVal) score -= 0.12;
  }
  return Math.max(0, score);
}

// ─────────────────────────────────────────────────────────────────────────────
// User-Agent consistency check
// ─────────────────────────────────────────────────────────────────────────────

function scoreUAConsistency(request: FlatCircleRequest, ja3Hash: string | undefined): number {
  const ua = request.headers["user-agent"] ?? request.headers["User-Agent"] ?? "";
  if (!ua) return 0.1;

  // Check if UA claims to be a browser but JA3 says otherwise
  const claimsBrowser = /Chrome|Firefox|Safari|Edge/i.test(ua);
  const ja3IsBrowser = ja3Hash ? KNOWN_BROWSER_JA3.has(ja3Hash) : null;
  const ja3IsBot = ja3Hash ? KNOWN_BOT_JA3.has(ja3Hash) : null;

  if (claimsBrowser && ja3IsBot) return 0.0;
  if (claimsBrowser && ja3IsBrowser) return 1.0;
  if (!claimsBrowser && !ja3IsBrowser) return 0.6;
  return 0.5;
}

// ─────────────────────────────────────────────────────────────────────────────
// ClientIntegrityScorer
// ─────────────────────────────────────────────────────────────────────────────

export class ClientIntegrityScorer {
  private readonly config: Layer19Config;
  private readonly cascade: ProviderCascade;
  private readonly emit: EventEmitterFn;
  private readonly merkle: MerkleIntegrityEngine | undefined;
  private readonly lowIntegrityThreshold: number;

  constructor(
    config: Layer19Config,
    cascade: ProviderCascade,
    emit: EventEmitterFn,
    merkle?: MerkleIntegrityEngine
  ) {
    this.config = config;
    this.cascade = cascade;
    this.emit = emit;
    this.merkle = merkle;
    this.lowIntegrityThreshold = config.lowIntegrityThreshold ?? 0.4;
  }

  /**
   * Score a client's integrity from TLS, HTTP/2, and UA signals.
   * Returns the score and whether the client should be routed to the honeypot.
   */
  score(input: ClientIntegrityInput): ClientIntegrityScore {
    const { request, tls, http2 } = input;

    // JA3 score
    let ja3Score = 0.5;
    let suspectedTool: string | null = null;
    if (this.config.ja3Enabled !== false && tls?.ja3Hash) {
      if (KNOWN_BROWSER_JA3.has(tls.ja3Hash)) {
        ja3Score = 1.0;
      } else if (KNOWN_BOT_JA3.has(tls.ja3Hash)) {
        ja3Score = 0.0;
        suspectedTool = KNOWN_BOT_JA3.get(tls.ja3Hash) ?? null;
      } else {
        ja3Score = 0.4; // Unknown — penalized but not condemned
      }
    }

    // HTTP/2 score
    const http2Score = this.config.http2FingerprintEnabled !== false
      ? scoreHttp2Fingerprint(http2)
      : 0.5;

    // UA consistency score
    const uaConsistencyScore = scoreUAConsistency(request, tls?.ja3Hash);

    // Weighted composite
    const score = ja3Score * 0.45 + http2Score * 0.30 + uaConsistencyScore * 0.25;
    const isLowIntegrity = score < this.lowIntegrityThreshold;

    return { score, ja3Score, http2Score, uaConsistencyScore, isLowIntegrity, suspectedTool };
  }

  /**
   * Process a request through client integrity scoring. Returns true if the
   * request should be routed to the honeypot mesh (Layer 2 integration).
   */
  async process(
    input: ClientIntegrityInput,
    providerTier: AIProviderTier
  ): Promise<{ route: "honeypot" | "normal" | "block"; integrityScore: ClientIntegrityScore }> {
    const integrityScore = this.score(input);

    if (!integrityScore.isLowIntegrity && (this.config.blockBelowScore == null || integrityScore.score >= this.config.blockBelowScore)) {
      return { route: "normal", integrityScore };
    }

    // Hard block if score is below blockBelowScore
    if (this.config.blockBelowScore != null && integrityScore.score < this.config.blockBelowScore) {
      const event = this.buildEvent("client.integrity.low", {
        score: integrityScore.score,
        suspectedTool: integrityScore.suspectedTool,
        action: "blocked",
      }, input.request, providerTier);
      this.emit(event);
      this.merkle?.recordHoneypotHit(event);
      return { route: "block", integrityScore };
    }

    // Route to honeypot
    if (this.config.layer2Integration !== false) {
      const event = this.buildEvent("client.integrity.low", {
        score: integrityScore.score,
        suspectedTool: integrityScore.suspectedTool,
        ja3Hash: input.tls?.ja3Hash ?? null,
        action: "routed-to-honeypot",
      }, input.request, providerTier);
      this.emit(event);
      this.merkle?.recordHoneypotHit(event);
      return { route: "honeypot", integrityScore };
    }

    return { route: "normal", integrityScore };
  }

  private buildEvent(
    type: FlatCircleEvent["type"],
    meta: Record<string, unknown>,
    request: FlatCircleRequest,
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
