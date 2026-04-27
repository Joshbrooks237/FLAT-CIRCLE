/**
 * Layer 17 — Authenticated Anomaly Engine
 *
 * Everything built so far assumes the attacker is outside.
 * Layer 17 assumes they got in.
 *
 * Authenticated users doing things authenticated users shouldn't —
 * privilege escalation, lateral movement through legitimate endpoints,
 * bulk data access, session reuse from unexpected locations.
 *
 * The same embedding and cosine distance approach as Layer 4,
 * but scoped to post-authentication behavior, per identity.
 *
 * A user who has accessed ten records a day for six months and suddenly
 * pulls ten thousand in an hour is not a DDoS. It is something quieter
 * and more dangerous.
 *
 * Layer 9 Session Shadowing activates automatically for flagged identities.
 */

import type {
  Layer17Config,
  AuthAnomalyClass,
  FlatCircleRequest,
  FlatCircleEvent,
  EventEmitterFn,
  AIProviderTier,
} from "../types.js";
import type { ProviderCascade } from "../provider-cascade.js";
import { cosineSimilarity } from "../provider-cascade.js";
import type { MerkleIntegrityEngine } from "./layer11-merkle.js";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface IdentityProfile {
  readonly identityId: string;
  baseline: number[];
  requestCount: number;
  baselineReady: boolean;
  endpointsAccessed: Set<string>;
  recordAccessLastHour: number;
  lastAccessAt: number;
  hourWindowStart: number;
}

export interface AuthnAnomalyEvent {
  readonly identityId: string;
  readonly anomalyClass: AuthAnomalyClass;
  readonly anomalyScore: number;
  readonly sessionId: string;
  readonly ip: string;
  readonly timestamp: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Static fallback classifier
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Deterministic anomaly classification without AI — used when AI tier is
 * unavailable. Classifies by request pattern heuristics alone.
 */
function staticClassify(
  profile: IdentityProfile,
  request: FlatCircleRequest,
  bulkThreshold: number
): AuthAnomalyClass {
  if (profile.recordAccessLastHour > bulkThreshold) return "bulk-exfiltration";
  if (!profile.endpointsAccessed.has(request.path) && profile.endpointsAccessed.size > 20) return "lateral-movement";
  if (request.path.includes("/admin") || request.path.includes("/internal")) return "privilege-escalation";
  return "unknown";
}

// ─────────────────────────────────────────────────────────────────────────────
// AuthenticatedAnomalyEngine
// ─────────────────────────────────────────────────────────────────────────────

const HOUR_MS = 3_600_000;

export class AuthenticatedAnomalyEngine {
  private readonly config: Layer17Config;
  private readonly cascade: ProviderCascade;
  private readonly emit: EventEmitterFn;
  private readonly merkle: MerkleIntegrityEngine | undefined;
  private readonly profiles = new Map<string, IdentityProfile>();
  private readonly learningWindow: number;
  private readonly anomalyThreshold: number;
  private readonly bulkAccessThreshold: number;
  private readonly identityHeader: string;

  constructor(
    config: Layer17Config,
    cascade: ProviderCascade,
    emit: EventEmitterFn,
    merkle?: MerkleIntegrityEngine
  ) {
    this.config = config;
    this.cascade = cascade;
    this.emit = emit;
    this.merkle = merkle;
    this.learningWindow = config.learningWindowRequests ?? 500;
    this.anomalyThreshold = config.anomalyThreshold ?? 0.35;
    this.bulkAccessThreshold = config.bulkAccessThreshold ?? 1000;
    this.identityHeader = config.identityHeader ?? "x-user-id";
  }

  /**
   * Process an authenticated request. Returns an anomaly event if the request
   * deviates from the identity's behavioral contract.
   */
  async process(
    request: FlatCircleRequest,
    providerTier: AIProviderTier
  ): Promise<AuthnAnomalyEvent | null> {
    const identityId = request.headers[this.identityHeader];
    if (!identityId) return null;

    const profile = this.getOrCreate(identityId);
    const now = Date.now();

    // Rolling hourly record count
    if (now - profile.hourWindowStart > HOUR_MS) {
      profile.recordAccessLastHour = 0;
      profile.hourWindowStart = now;
    }
    profile.recordAccessLastHour++;
    profile.endpointsAccessed.add(request.path);
    profile.lastAccessAt = now;

    // Embed the request for behavioral comparison
    const requestText = `${request.method} ${request.path} ${JSON.stringify(request.query)}`;
    let embedding: number[];
    try {
      const result = await this.cascade.embed({ text: requestText });
      embedding = result.embedding;
    } catch {
      // Static fallback: deterministic embedding based on path hash
      embedding = Array.from({ length: 384 }, (_, i) =>
        Math.sin((i + requestText.charCodeAt(i % requestText.length)) * 0.1) * 0.5
      );
    }

    // During learning window — accumulate baseline
    if (profile.requestCount < this.learningWindow) {
      this.updateBaseline(profile, embedding);
      profile.requestCount++;
      return null;
    }

    profile.baselineReady = true;
    profile.requestCount++;

    // Compute anomaly score
    const similarity = profile.baseline.length > 0
      ? cosineSimilarity(embedding, profile.baseline)
      : 1;
    const distance = 1 - similarity;

    const bulkAnomaly = profile.recordAccessLastHour > this.bulkAccessThreshold;

    if (distance < this.anomalyThreshold && !bulkAnomaly) {
      this.updateBaseline(profile, embedding);
      return null;
    }

    // Anomaly detected
    const anomalyClass = this.config.aiClassification !== false && providerTier !== "static"
      ? await this.classifyWithAI(request, profile, distance, providerTier)
      : staticClassify(profile, request, this.bulkAccessThreshold);

    const anomalyEvent: AuthnAnomalyEvent = {
      identityId,
      anomalyClass,
      anomalyScore: distance,
      sessionId: request.sessionId,
      ip: request.ip,
      timestamp: now,
    };

    const event = this.buildEvent("authn.anomaly.detected", {
      identityId,
      anomalyClass,
      anomalyScore: distance,
      bulkAccessCount: profile.recordAccessLastHour,
      endpointCount: profile.endpointsAccessed.size,
    }, request, providerTier);

    this.emit(event);
    this.merkle?.recordHoneypotHit(event);

    return anomalyEvent;
  }

  private getOrCreate(identityId: string): IdentityProfile {
    let profile = this.profiles.get(identityId);
    if (!profile) {
      profile = {
        identityId,
        baseline: [],
        requestCount: 0,
        baselineReady: false,
        endpointsAccessed: new Set(),
        recordAccessLastHour: 0,
        lastAccessAt: Date.now(),
        hourWindowStart: Date.now(),
      };
      this.profiles.set(identityId, profile);
    }
    return profile;
  }

  private updateBaseline(profile: IdentityProfile, embedding: number[]): void {
    if (profile.baseline.length === 0) {
      profile.baseline = [...embedding];
      return;
    }
    // Exponential moving average
    const alpha = 2 / (Math.min(profile.requestCount, this.learningWindow) + 1);
    profile.baseline = profile.baseline.map((v, i) =>
      alpha * (embedding[i] ?? 0) + (1 - alpha) * v
    );
  }

  private async classifyWithAI(
    request: FlatCircleRequest,
    profile: IdentityProfile,
    anomalyScore: number,
    providerTier: AIProviderTier
  ): Promise<AuthAnomalyClass> {
    try {
      const result = await this.cascade.generate({
        system: "You are a security anomaly classifier. Respond with one of: credential-compromise, malicious-insider, automated-scraping, privilege-escalation, lateral-movement, bulk-exfiltration, unknown",
        prompt: `Authenticated identity behavior anomaly. Score: ${anomalyScore.toFixed(3)}. Path: ${request.path}. Method: ${request.method}. Bulk access last hour: ${profile.recordAccessLastHour}. Unique endpoints: ${profile.endpointsAccessed.size}. Classify the anomaly type.`,
        maxTokens: 20,
        temperature: 0,
      });
      const text = result.text.trim().toLowerCase() as AuthAnomalyClass;
      const valid: AuthAnomalyClass[] = [
        "credential-compromise", "malicious-insider", "automated-scraping",
        "privilege-escalation", "lateral-movement", "bulk-exfiltration",
      ];
      return valid.includes(text) ? text : "unknown";
    } catch {
      return staticClassify(profile, request, this.bulkAccessThreshold);
    }
  }

  getProfiles(): ReadonlyMap<string, IdentityProfile> {
    return this.profiles;
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
