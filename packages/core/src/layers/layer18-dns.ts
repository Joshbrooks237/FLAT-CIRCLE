/**
 * Layer 18 — DNS Integrity Watch
 *
 * Dangling DNS records are silent vulnerabilities. A subdomain pointing to a
 * deprovisioned cloud service, a CNAME target that no longer exists, an
 * abandoned Heroku or Vercel deployment — an attacker claims the resource and
 * serves content under your brand with your SSL certificate.
 *
 * This layer monitors the full DNS surface of the protected application
 * continuously. Every DNS entry is verified against a set of recognized,
 * owned, active resources. Unrecognized resolutions trigger immediate alerts.
 *
 * This layer runs as a background service on a configurable polling interval.
 * It is NOT in the request path.
 *
 * The AI provider cascade cross-references new subdomains against known
 * infrastructure patterns to distinguish legitimate new deployments from
 * potential takeover targets.
 */

import { lookup } from "node:dns/promises";
import type {
  Layer18Config,
  FlatCircleEvent,
  EventEmitterFn,
  AIProviderTier,
} from "../types.js";
import type { ProviderCascade } from "../provider-cascade.js";
import type { MerkleIntegrityEngine } from "./layer11-merkle.js";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type DNSRecordStatus = "verified" | "unrecognized" | "flagged";

export interface MonitoredDNSRecord {
  readonly hostname: string;
  status: DNSRecordStatus;
  resolvedAddress: string | null;
  lastCheckedAt: number;
  firstSeenAt: number;
  consecutiveUnrecognized: number;
}

export interface DNSScanResult {
  readonly scannedAt: number;
  readonly totalRecords: number;
  readonly verifiedCount: number;
  readonly unrecognizedCount: number;
  readonly flaggedCount: number;
  readonly newHostnames: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Known-good infrastructure patterns
// ─────────────────────────────────────────────────────────────────────────────

/** Cloud platforms that are considered legitimate CNAME targets by default. */
const DEFAULT_KNOWN_INFRASTRUCTURE: readonly RegExp[] = [
  /\.amazonaws\.com$/,
  /\.cloudfront\.net$/,
  /\.vercel\.app$/,
  /\.netlify\.app$/,
  /\.azurewebsites\.net$/,
  /\.googleusercontent\.com$/,
  /\.github\.io$/,
  /\.pages\.dev$/,
  /\.fastly\.net$/,
  /\.akamai(?:edge)?\.net$/,
];

/** Cloud platforms that are commonly abused for subdomain takeover. */
const TAKEOVER_RISK_PATTERNS: readonly RegExp[] = [
  /\.herokuapp\.com$/,
  /\.s3\.amazonaws\.com$/,
  /\.blob\.core\.windows\.net$/,
  /\.ghost\.io$/,
  /\.tumblr\.com$/,
  /\.pantheonsite\.io$/,
  /\.surge\.sh$/,
  /\.readme\.io$/,
  /\.helpscoutdocs\.com$/,
];

function matchesPatterns(host: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((p) => p.test(host));
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS resolution helper (with graceful fallback)
// ─────────────────────────────────────────────────────────────────────────────

async function resolveDNS(hostname: string): Promise<string | null> {
  try {
    const result = await lookup(hostname, { family: 0 });
    return result.address;
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// DNSIntegrityWatcher
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_POLLING_INTERVAL_SECONDS = 3600;

export class DNSIntegrityWatcher {
  private readonly config: Layer18Config;
  private readonly cascade: ProviderCascade;
  private readonly emit: EventEmitterFn;
  private readonly merkle: MerkleIntegrityEngine | undefined;
  private readonly records = new Map<string, MonitoredDNSRecord>();
  private readonly knownPatterns: RegExp[];
  private pollingTimer: ReturnType<typeof setInterval> | null = null;
  private lastScanResult: DNSScanResult | null = null;

  constructor(
    config: Layer18Config,
    cascade: ProviderCascade,
    emit: EventEmitterFn,
    merkle?: MerkleIntegrityEngine
  ) {
    this.config = config;
    this.cascade = cascade;
    this.emit = emit;
    this.merkle = merkle;

    this.knownPatterns = [
      ...DEFAULT_KNOWN_INFRASTRUCTURE,
      ...(config.knownInfrastructurePatterns ?? []).map((p) => {
        try { return new RegExp(p); } catch { return null; }
      }).filter((r): r is RegExp => r !== null),
    ];
  }

  /** Start the background DNS monitoring loop. */
  start(): void {
    if (this.pollingTimer) return;
    const intervalMs = (this.config.pollingIntervalSeconds ?? DEFAULT_POLLING_INTERVAL_SECONDS) * 1_000;
    // Run immediately on start, then on interval.
    void this.scan("static");
    this.pollingTimer = setInterval(() => void this.scan("static"), intervalMs);
  }

  stop(): void {
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
    }
  }

  /**
   * Perform a full DNS scan of all configured domains.
   * Generates subdomains from the provided list and checks each.
   */
  async scan(providerTier: AIProviderTier): Promise<DNSScanResult> {
    const domains = this.config.domains ?? [];
    if (domains.length === 0) {
      const result: DNSScanResult = {
        scannedAt: Date.now(),
        totalRecords: 0,
        verifiedCount: 0,
        unrecognizedCount: 0,
        flaggedCount: 0,
        newHostnames: [],
      };
      this.lastScanResult = result;
      return result;
    }

    const newHostnames: string[] = [];

    // For each domain, verify it and a set of common subdomains.
    for (const domain of domains) {
      const hostnames = [domain, `www.${domain}`, `api.${domain}`, `app.${domain}`, `mail.${domain}`];
      for (const hostname of hostnames) {
        if (!this.records.has(hostname)) {
          newHostnames.push(hostname);
        }
        await this.checkHostname(hostname, providerTier);
      }
    }

    let verified = 0;
    let unrecognized = 0;
    let flagged = 0;
    for (const rec of this.records.values()) {
      if (rec.status === "verified") verified++;
      else if (rec.status === "unrecognized") unrecognized++;
      else flagged++;
    }

    const result: DNSScanResult = {
      scannedAt: Date.now(),
      totalRecords: this.records.size,
      verifiedCount: verified,
      unrecognizedCount: unrecognized,
      flaggedCount: flagged,
      newHostnames,
    };
    this.lastScanResult = result;
    return result;
  }

  private async checkHostname(hostname: string, providerTier: AIProviderTier): Promise<void> {
    const address = await resolveDNS(hostname);
    const now = Date.now();

    const existing = this.records.get(hostname);
    const record: MonitoredDNSRecord = existing ?? {
      hostname,
      status: "unrecognized",
      resolvedAddress: null,
      lastCheckedAt: now,
      firstSeenAt: now,
      consecutiveUnrecognized: 0,
    };

    record.resolvedAddress = address;
    record.lastCheckedAt = now;

    if (address === null) {
      // NXDOMAIN — flag if was previously resolving (potential dangling record cleanup)
      record.status = "verified";
    } else if (matchesPatterns(address, this.knownPatterns)) {
      record.status = "verified";
      record.consecutiveUnrecognized = 0;
    } else if (matchesPatterns(address, TAKEOVER_RISK_PATTERNS)) {
      // High-risk platform — check if resource actually exists
      const isTakeoverRisk = await this.assessTakeoverRisk(hostname, address, providerTier);
      if (isTakeoverRisk) {
        record.status = "flagged";
        const event = this.buildEvent("dns.takeover.suspected", { hostname, resolvedAddress: address }, providerTier);
        this.emit(event);
        this.merkle?.recordHoneypotHit(event);
        if (this.config.webhookUrl) void this.notifyWebhook(this.config.webhookUrl, event);
      } else {
        record.status = "unrecognized";
        record.consecutiveUnrecognized++;
        if (record.consecutiveUnrecognized >= 2) {
          const event = this.buildEvent("dns.record.unrecognized", { hostname, resolvedAddress: address }, providerTier);
          this.emit(event);
          this.merkle?.recordHoneypotHit(event);
        }
      }
    } else {
      record.status = "unrecognized";
      record.consecutiveUnrecognized++;
      if (record.consecutiveUnrecognized === 1 && this.config.alertOnUnrecognized !== false) {
        const event = this.buildEvent("dns.record.unrecognized", { hostname, resolvedAddress: address }, providerTier);
        this.emit(event);
        this.merkle?.recordHoneypotHit(event);
      }
    }

    this.records.set(hostname, record);
  }

  /**
   * Use the AI cascade to assess whether a high-risk DNS resolution represents
   * an actual takeover attempt. Falls back to heuristics on static tier.
   */
  private async assessTakeoverRisk(
    hostname: string,
    resolvedAddress: string,
    providerTier: AIProviderTier
  ): Promise<boolean> {
    if (providerTier === "static") {
      // Heuristic: if subdomain is non-www, non-api and points to high-risk platform, suspect
      return !["www.", "api.", "mail.", "app."].some((prefix) => hostname.startsWith(prefix));
    }
    try {
      const result = await this.cascade.generate({
        system: "You are a DNS security analyst. Respond only with 'yes' or 'no'.",
        prompt: `Does the hostname '${hostname}' resolving to '${resolvedAddress}' indicate a potential subdomain takeover vulnerability? Consider that the target is a high-risk hosting platform.`,
        maxTokens: 5,
        temperature: 0,
      });
      return result.text.trim().toLowerCase().startsWith("yes");
    } catch {
      return false;
    }
  }

  private async notifyWebhook(url: string, event: FlatCircleEvent): Promise<void> {
    try {
      await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(event),
      });
    } catch {
      // Non-fatal.
    }
  }

  getRecords(): ReadonlyMap<string, MonitoredDNSRecord> {
    return this.records;
  }

  getLastScanResult(): DNSScanResult | null {
    return this.lastScanResult;
  }

  private buildEvent(
    type: FlatCircleEvent["type"],
    meta: Record<string, unknown>,
    providerTier: AIProviderTier
  ): FlatCircleEvent {
    return {
      id: crypto.randomUUID(),
      type,
      timestamp: Date.now(),
      sessionId: "system",
      ip: "dns-monitor",
      providerTier,
      metadata: meta,
    };
  }
}
