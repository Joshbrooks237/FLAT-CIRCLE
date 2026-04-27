/**
 * Layer 20 — Exfiltration Velocity Monitor
 *
 * Behavioral contracts and DDoS detection both respond to spikes.
 * Layer 20 responds to the absence of spikes — the slow bleed.
 *
 * An authenticated identity copying your database one record at a time,
 * under rate limits, over days or weeks, through completely normal API calls
 * that individually trigger nothing. The cumulative transfer is the signal.
 *
 * This layer tracks data transfer volume per authenticated identity, per
 * endpoint, and per data classification over configurable rolling windows.
 * When cumulative transfer crosses a threshold that no legitimate use case
 * explains, the layer escalates.
 *
 * The AI contextualizes the anomaly — distinguishing a data analyst running
 * a legitimate large export from an exfiltration pattern that mirrors known
 * threat actor behavior.
 *
 * The static fallback uses rolling sum thresholds with configurable decay.
 * This layer never requires an AI provider to function.
 *
 * Layer 9 Session Shadowing activates automatically for flagged identities.
 */

import type {
  Layer20Config,
  ExfiltrationThresholds,
  FlatCircleRequest,
  FlatCircleResponse,
  FlatCircleEvent,
  EventEmitterFn,
  AIProviderTier,
} from "../types.js";
import type { ProviderCascade } from "../provider-cascade.js";
import type { MerkleIntegrityEngine } from "./layer11-merkle.js";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface TransferSample {
  readonly timestamp: number;
  readonly bytes: number;
  readonly endpoint: string;
}

export interface IdentityVelocityProfile {
  readonly identityId: string;
  samples: TransferSample[];
  totalBytesAllTime: number;
  lastEscalatedAt: number | null;
}

export interface VelocityCheckResult {
  readonly identityId: string;
  readonly bytesHourly: number;
  readonly bytesDaily: number;
  readonly bytesWeekly: number;
  readonly bytesMonthly: number;
  readonly exceeded: boolean;
  readonly exceedingWindow: "hourly" | "daily" | "weekly" | "monthly" | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Default thresholds
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_THRESHOLDS: Required<ExfiltrationThresholds> = {
  hourlyBytes:  100 * 1024 * 1024,   // 100 MB/hr
  dailyBytes:   500 * 1024 * 1024,   // 500 MB/day
  weeklyBytes:  2   * 1024 * 1024 * 1024, // 2 GB/week
  monthlyBytes: 8   * 1024 * 1024 * 1024, // 8 GB/month
};

// ─────────────────────────────────────────────────────────────────────────────
// Rolling window calculation with exponential decay
// ─────────────────────────────────────────────────────────────────────────────

const HOUR_MS  = 3_600_000;
const DAY_MS   = 24 * HOUR_MS;
const WEEK_MS  = 7  * DAY_MS;
const MONTH_MS = 30 * DAY_MS;

/**
 * Sum bytes in a rolling window, applying exponential decay so older samples
 * contribute less. The half-life is the time in milliseconds after which
 * a sample contributes at 50% weight.
 */
function rollingSum(samples: TransferSample[], windowMs: number, halfLifeMs: number, now: number): number {
  const cutoff = now - windowMs;
  return samples
    .filter((s) => s.timestamp >= cutoff)
    .reduce((sum, s) => {
      const age = now - s.timestamp;
      const weight = Math.pow(0.5, age / halfLifeMs);
      return sum + s.bytes * weight;
    }, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Response byte estimation
// ─────────────────────────────────────────────────────────────────────────────

function estimateResponseBytes(response: FlatCircleResponse): number {
  if (typeof response.body === "string") return response.body.length;
  try {
    return JSON.stringify(response.body).length;
  } catch {
    return 512; // Fallback estimate
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExfiltrationVelocityMonitor
// ─────────────────────────────────────────────────────────────────────────────

export class ExfiltrationVelocityMonitor {
  private readonly config: Layer20Config;
  private readonly cascade: ProviderCascade;
  private readonly emit: EventEmitterFn;
  private readonly merkle: MerkleIntegrityEngine | undefined;
  private readonly profiles = new Map<string, IdentityVelocityProfile>();
  private readonly thresholds: Required<ExfiltrationThresholds>;
  private readonly halfLifeMs: number;
  private readonly identityHeader: string;
  /** Prune samples older than this to bound memory usage. */
  private readonly maxSampleAgeMs = MONTH_MS;

  constructor(
    config: Layer20Config,
    cascade: ProviderCascade,
    emit: EventEmitterFn,
    merkle?: MerkleIntegrityEngine
  ) {
    this.config = config;
    this.cascade = cascade;
    this.emit = emit;
    this.merkle = merkle;
    this.identityHeader = config.identityHeader ?? "x-user-id";
    this.halfLifeMs = (config.decayHalfLifeHours ?? 24) * HOUR_MS;

    const t = config.thresholds ?? {};
    this.thresholds = {
      hourlyBytes:  t.hourlyBytes  ?? DEFAULT_THRESHOLDS.hourlyBytes,
      dailyBytes:   t.dailyBytes   ?? DEFAULT_THRESHOLDS.dailyBytes,
      weeklyBytes:  t.weeklyBytes  ?? DEFAULT_THRESHOLDS.weeklyBytes,
      monthlyBytes: t.monthlyBytes ?? DEFAULT_THRESHOLDS.monthlyBytes,
    };
  }

  /**
   * Record the bytes transferred for an authenticated request/response pair
   * and check velocity thresholds. Returns a check result if thresholds are
   * exceeded, null otherwise.
   */
  async record(
    request: FlatCircleRequest,
    response: FlatCircleResponse,
    providerTier: AIProviderTier
  ): Promise<VelocityCheckResult | null> {
    const identityId = request.headers[this.identityHeader];
    if (!identityId) return null;

    const bytes = estimateResponseBytes(response);
    const sample: TransferSample = { timestamp: Date.now(), bytes, endpoint: request.path };

    const profile = this.getOrCreate(identityId);
    profile.samples.push(sample);
    profile.totalBytesAllTime += bytes;

    // Prune old samples to bound memory
    const cutoff = Date.now() - this.maxSampleAgeMs;
    profile.samples = profile.samples.filter((s) => s.timestamp >= cutoff);

    return this.checkVelocity(profile, request, providerTier);
  }

  private async checkVelocity(
    profile: IdentityVelocityProfile,
    request: FlatCircleRequest,
    providerTier: AIProviderTier
  ): Promise<VelocityCheckResult | null> {
    const now = Date.now();
    const halfLife = this.halfLifeMs;

    const bytesHourly  = rollingSum(profile.samples, HOUR_MS,  halfLife, now);
    const bytesDaily   = rollingSum(profile.samples, DAY_MS,   halfLife, now);
    const bytesWeekly  = rollingSum(profile.samples, WEEK_MS,  halfLife, now);
    const bytesMonthly = rollingSum(profile.samples, MONTH_MS, halfLife, now);

    let exceedingWindow: VelocityCheckResult["exceedingWindow"] = null;
    if (bytesHourly  > this.thresholds.hourlyBytes)  exceedingWindow = "hourly";
    else if (bytesDaily  > this.thresholds.dailyBytes)  exceedingWindow = "daily";
    else if (bytesWeekly > this.thresholds.weeklyBytes) exceedingWindow = "weekly";
    else if (bytesMonthly > this.thresholds.monthlyBytes) exceedingWindow = "monthly";

    if (!exceedingWindow) return null;

    // Debounce: don't re-escalate within 1 hour
    if (profile.lastEscalatedAt && now - profile.lastEscalatedAt < HOUR_MS) return null;
    profile.lastEscalatedAt = now;

    const contextualAnomaly = this.config.aiClassification !== false && providerTier !== "static"
      ? await this.classifyWithAI(profile, bytesHourly, bytesDaily, exceedingWindow, providerTier)
      : null;

    const event = this.buildEvent("exfiltration.velocity.exceeded", {
      identityId: profile.identityId,
      exceedingWindow,
      bytesHourly,
      bytesDaily,
      bytesWeekly,
      bytesMonthly,
      threshold: this.thresholds[`${exceedingWindow}Bytes` as keyof Required<ExfiltrationThresholds>],
      contextualAnomaly,
      endpoint: request.path,
    }, request, providerTier);

    this.emit(event);
    this.merkle?.recordHoneypotHit(event);

    return {
      identityId: profile.identityId,
      bytesHourly,
      bytesDaily,
      bytesWeekly,
      bytesMonthly,
      exceeded: true,
      exceedingWindow,
    };
  }

  private async classifyWithAI(
    profile: IdentityVelocityProfile,
    bytesHourly: number,
    bytesDaily: number,
    exceedingWindow: string,
    providerTier: AIProviderTier
  ): Promise<string | null> {
    try {
      const result = await this.cascade.generate({
        system: "You are a data exfiltration analyst. Respond in one sentence.",
        prompt: `Identity '${profile.identityId}' has transferred ${(bytesDaily / 1_048_576).toFixed(1)} MB today, exceeding the ${exceedingWindow} threshold. The transfer involved ${new Set(profile.samples.slice(-50).map((s) => s.endpoint)).size} distinct endpoints. Is this consistent with legitimate bulk export or exfiltration behavior?`,
        maxTokens: 60,
      });
      return result.text;
    } catch {
      return null;
    }
  }

  private getOrCreate(identityId: string): IdentityVelocityProfile {
    let profile = this.profiles.get(identityId);
    if (!profile) {
      profile = { identityId, samples: [], totalBytesAllTime: 0, lastEscalatedAt: null };
      this.profiles.set(identityId, profile);
    }
    return profile;
  }

  getProfile(identityId: string): IdentityVelocityProfile | undefined {
    return this.profiles.get(identityId);
  }

  getProfiles(): ReadonlyMap<string, IdentityVelocityProfile> {
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
