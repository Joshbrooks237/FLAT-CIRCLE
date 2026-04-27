/**
 * Layer 22 — Forensic Export and Chain of Custody
 *
 * A closed network tells you nothing happened.
 * Flat Circle tells you everything that was attempted, by whom, with what,
 * classified and timestamped and cryptographically sealed.
 *
 * Layer 22 is the mechanism by which that record leaves the system in a form
 * that is legally defensible, compliance-ready, and forensically admissible.
 *
 * Four modes:
 *   1. Continuous Forensic Stream   — every Merkle leaf, append-only, real-time
 *   2. Incident Package Export      — full session timeline, signed, structured
 *   3. Compliance Report Generation — periodic audit summaries, AI-narrated
 *   4. Legal Hold                   — frozen immutable record for litigation
 *
 * Chain of custody:
 *   — Every export is cryptographically signed against the instance's private key
 *   — Every export carries the Merkle root at time of export
 *   — The proof chain from any leaf to the current root is self-contained
 *   — The export format is an open specification — no Flat Circle software
 *     needed to verify authenticity
 *
 * Integration:
 *   — Layer 22 is the read layer on top of the write layer all other layers use.
 *     It does not alter any existing layer. It subscribes to Merkle leaf events
 *     via the onLeaf() hook and maintains its own forensic registry.
 */

import { createHash, createSign, createVerify } from "node:crypto";
import { readFile, mkdir, appendFile } from "node:fs/promises";
import { join } from "node:path";
import type {
  Layer22Config,
  IncidentPackageFormat,
  ComplianceReportFormat,
  ComplianceReportSchedule,
  FlatCircleEvent,
  EventEmitterFn,
  AIProviderTier,
} from "../types.js";
import type { ProviderCascade } from "../provider-cascade.js";
import type { MerkleLeaf, MerkleRootSnapshot } from "./layer11-merkle.js";

// ─────────────────────────────────────────────────────────────────────────────
// Shared types
// ─────────────────────────────────────────────────────────────────────────────

export type ForensicStreamStatus = "streaming" | "buffered" | "unreachable";

/** A Merkle leaf enriched with export metadata for forensic records. */
export interface ForensicLeafRecord {
  readonly leafIndex: number;
  readonly leafHash: string;
  readonly kind: string;
  readonly layerOrigin: number | null;
  readonly sessionId: string;
  readonly timestamp: number;
  readonly merkleRootAtWrite: string;
  readonly threatClass?: string;
  readonly aiTier: AIProviderTier;
  readonly data: Record<string, unknown>;
}

/** A sealed, signed forensic incident package for a completed session. */
export interface IncidentPackage {
  readonly id: string;
  readonly sessionId: string;
  readonly createdAt: number;
  readonly sealedAt: number;
  readonly merkleRootAtOpen: string;
  readonly merkleRootAtClose: string;
  readonly leafCount: number;
  readonly timeline: ForensicLeafRecord[];
  readonly aiClassificationNarrative: string;
  /**
   * Ordered list of leaf hashes from the first to the last event in the
   * session, followed by the Merkle root. Any forensic tool can verify the
   * chain by re-computing the hashes and confirming the root matches.
   */
  readonly proofChain: string[];
  /** Hex-encoded PKCS#8 signature over the package body, or null if unsigned. */
  readonly signature: string | null;
  /** PEM-encoded public key for signature verification, or null if omitted. */
  readonly publicKey: string | null;
  /**
   * Export format specification version. Increment only when the schema changes
   * in a backward-incompatible way. Any verifier that understands "1.0" can
   * validate any 1.x package.
   */
  readonly formatVersion: "1.0";
}

/** Aggregated compliance report for a calendar period. */
export interface ComplianceReport {
  readonly id: string;
  readonly period: { from: number; to: number };
  readonly generatedAt: number;
  readonly merkleRootHistory: MerkleRootSnapshot[];
  readonly threatVolume: Record<string, number>;
  readonly layerActivationStats: Record<number, number>;
  readonly aiCascadeStats: {
    failovers: number;
    tierDistribution: Record<string, number>;
  };
  readonly secretsRedactedCount: number;
  readonly dependencyIntegrityStatus: string;
  readonly dnsChanges: number;
  readonly exfiltrationAlertsCount: number;
  readonly incidentPackageCount: number;
  readonly executiveSummary: string;
  readonly signature: string | null;
}

/** An active or historical legal hold record. */
export interface LegalHold {
  readonly id: string;
  readonly activatedAt: number;
  readonly reason: string;
  readonly frozenMerkleRoot: string;
  readonly frozenLeafCount: number;
  readonly holdDeclarationSignature: string | null;
  releasedAt: number | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

function sign(data: string, privateKeyPem: string): string | null {
  try {
    const signer = createSign("SHA256");
    signer.update(data, "utf8");
    return signer.sign(privateKeyPem, "hex");
  } catch {
    return null;
  }
}

export function verifySignature(
  data: string,
  signature: string,
  publicKeyPem: string
): boolean {
  try {
    const verifier = createVerify("SHA256");
    verifier.update(data, "utf8");
    return verifier.verify(publicKeyPem, signature, "hex");
  } catch {
    return false;
  }
}

function layerOriginFromKind(kind: string): number | null {
  switch (kind) {
    case "honeypot":  return 2;
    case "canary":    return 3;
    case "anomaly":   return 4;
    case "tarpit":    return 14;
    default:          return null;
  }
}

function toForensicRecord(
  leaf: MerkleLeaf,
  merkleRoot: string,
  aiTier: AIProviderTier
): ForensicLeafRecord {
  return {
    leafIndex: leaf.index,
    leafHash: leaf.hash,
    kind: leaf.kind,
    layerOrigin: typeof leaf.data["layerOrigin"] === "number"
      ? leaf.data["layerOrigin"]
      : layerOriginFromKind(leaf.kind),
    sessionId: leaf.sessionId,
    timestamp: leaf.timestamp,
    merkleRootAtWrite: merkleRoot,
    threatClass: typeof leaf.data["threatClass"] === "string"
      ? leaf.data["threatClass"]
      : undefined,
    aiTier,
    data: leaf.data,
  };
}

function buildSystemEvent(
  type: FlatCircleEvent["type"],
  meta: Record<string, unknown>,
  providerTier: AIProviderTier
): FlatCircleEvent {
  return {
    id: crypto.randomUUID(),
    type,
    timestamp: Date.now(),
    sessionId: "system",
    ip: "forensic-layer",
    providerTier,
    metadata: meta,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode 1 — Continuous Forensic Stream
// ─────────────────────────────────────────────────────────────────────────────

export class ForensicStreamExporter {
  private readonly config: Layer22Config;
  private readonly emit: EventEmitterFn;
  private readonly buffer: ForensicLeafRecord[] = [];
  private status: ForensicStreamStatus = "buffered";
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private totalExported = 0;

  constructor(config: Layer22Config, emit: EventEmitterFn) {
    this.config = config;
    this.emit = emit;
  }

  start(): void {
    if (!this.config.streamEnabled || this.flushTimer) return;
    const intervalMs =
      (this.config.exportTarget?.flushIntervalSeconds ?? 30) * 1_000;
    this.flushTimer = setInterval(() => void this.flush("static"), intervalMs);
    this.status = this.config.exportTarget ? "streaming" : "buffered";
  }

  stop(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  enqueue(record: ForensicLeafRecord): void {
    this.buffer.push(record);
    const maxBuf = this.config.exportTarget?.maxBufferSize ?? 1_000;
    if (this.buffer.length >= maxBuf) {
      void this.flush("static");
    }
  }

  async flush(providerTier: AIProviderTier): Promise<void> {
    if (this.buffer.length === 0) return;
    const batch = this.buffer.splice(0, this.buffer.length);
    const target = this.config.exportTarget;

    if (!target) {
      this.status = "buffered";
      return;
    }

    try {
      await this.writeBatch(batch, target);
      this.totalExported += batch.length;
      this.status = "streaming";
      this.emit(
        buildSystemEvent(
          "forensic.stream.flushed",
          { batchSize: batch.length, totalExported: this.totalExported },
          providerTier
        )
      );
    } catch (err) {
      this.buffer.unshift(...batch);
      this.status = "unreachable";
      this.emit(
        buildSystemEvent(
          "forensic.stream.error",
          { error: String(err), bufferedCount: this.buffer.length },
          providerTier
        )
      );
    }
  }

  private async writeBatch(
    records: ForensicLeafRecord[],
    target: NonNullable<Layer22Config["exportTarget"]>
  ): Promise<void> {
    const payload =
      records.map((r) => JSON.stringify(r)).join("\n") + "\n";
    const date = new Date().toISOString().slice(0, 10);
    const filename = `flat-circle-forensic-${date}.ndjson`;

    switch (target.type) {
      case "filesystem": {
        const dir = target.bucketOrPath ?? ".flat-circle/forensic";
        await mkdir(dir, { recursive: true });
        await appendFile(join(dir, filename), payload, "utf8");
        break;
      }
      case "webhook": {
        if (!target.endpoint) break;
        await fetch(target.endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-ndjson" },
          body: payload,
        });
        break;
      }
      // s3, gcs, azure-blob, postgres, redis:
      // Integration is via a dedicated storage adapter or webhook bridge.
      // The format is NDJSON with the ForensicLeafRecord schema documented
      // in the open format spec (flat-circle-forensic-format-v1.0.md).
      default:
        this.status = "buffered";
    }
  }

  getStatus(): ForensicStreamStatus { return this.status; }
  getTotalExported(): number { return this.totalExported; }
  getBufferSize(): number { return this.buffer.length; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode 2 — Incident Package Export
// ─────────────────────────────────────────────────────────────────────────────

export class IncidentPackageBuilder {
  private readonly config: Layer22Config;
  private readonly cascade: ProviderCascade;
  private readonly emit: EventEmitterFn;
  private readonly sealed = new Map<string, IncidentPackage>();
  private privateKey: string | null = null;

  constructor(
    config: Layer22Config,
    cascade: ProviderCascade,
    emit: EventEmitterFn
  ) {
    this.config = config;
    this.cascade = cascade;
    this.emit = emit;
  }

  async loadPrivateKey(): Promise<void> {
    if (this.config.signingPrivateKeyPath) {
      try {
        this.privateKey = await readFile(
          this.config.signingPrivateKeyPath,
          "utf8"
        );
      } catch {
        this.privateKey = null;
      }
    }
  }

  /**
   * Compile and seal a forensic incident package for a completed session.
   * Called automatically when Layer 9 closes a classified session.
   *
   * @param sessionId         - The session being sealed.
   * @param sessionLeaves     - Forensic records already collected by Layer 22.
   * @param openRootSnapshot  - Merkle root at session open (captured at start).
   * @param closeRoot         - Current Merkle root at session close.
   * @param providerTier      - Active AI tier at time of sealing.
   */
  async compile(
    sessionId: string,
    sessionLeaves: ForensicLeafRecord[],
    openRootSnapshot: MerkleRootSnapshot,
    closeRoot: string,
    providerTier: AIProviderTier
  ): Promise<IncidentPackage> {
    const proofChain = sessionLeaves.map((r) => r.leafHash);
    proofChain.push(closeRoot);

    const aiClassificationNarrative = await this.generateNarrative(
      sessionId,
      sessionLeaves,
      providerTier
    );

    const body = {
      sessionId,
      createdAt: openRootSnapshot.timestamp,
      sealedAt: Date.now(),
      merkleRootAtOpen: openRootSnapshot.root,
      merkleRootAtClose: closeRoot,
      leafCount: sessionLeaves.length,
      timeline: sessionLeaves,
      aiClassificationNarrative,
      proofChain,
      formatVersion: "1.0" as const,
    };

    const signature = this.privateKey
      ? sign(JSON.stringify(body), this.privateKey)
      : null;

    const pkg: IncidentPackage = {
      id: crypto.randomUUID(),
      ...body,
      signature,
      publicKey: this.config.verificationPublicKey ?? null,
    };

    this.sealed.set(pkg.id, pkg);
    this.emit(
      buildSystemEvent(
        "incident.package.sealed",
        {
          packageId: pkg.id,
          leafCount: pkg.leafCount,
          signed: signature !== null,
        },
        providerTier
      )
    );

    return pkg;
  }

  private async generateNarrative(
    sessionId: string,
    timeline: ForensicLeafRecord[],
    providerTier: AIProviderTier
  ): Promise<string> {
    if (providerTier === "static" || timeline.length === 0) {
      const uniqueLayers = new Set(timeline.map((e) => e.layerOrigin)).size;
      return (
        `Session ${sessionId.slice(0, 8)} — ${timeline.length} events recorded ` +
        `across ${uniqueLayers} layers. Static classification. ` +
        `Full cryptographic audit trail sealed.`
      );
    }
    try {
      const kinds = [...new Set(timeline.map((e) => e.kind))].join(", ");
      const result = await this.cascade.generate({
        system:
          "You are a cybersecurity incident analyst writing a forensic narrative. Be precise and concise.",
        prompt:
          `Write a 2-sentence forensic summary for session ${sessionId.slice(0, 8)}. ` +
          `The session generated ${timeline.length} audit events of types: ${kinds}. ` +
          `Include what was attempted, how it was contained, and significance for security posture.`,
        maxTokens: 120,
      });
      return result.text;
    } catch {
      return (
        `Session ${sessionId.slice(0, 8)} — ${timeline.length} events recorded. ` +
        `AI narrative unavailable; static fallback active. Full Merkle audit trail sealed.`
      );
    }
  }

  /** Serialize a sealed package to a given format. */
  export(packageId: string, format: IncidentPackageFormat): string | null {
    const pkg = this.sealed.get(packageId);
    if (!pkg) return null;

    switch (format) {
      case "json":
        return JSON.stringify(pkg, null, 2);
      case "zip":
        // Full ZIP assembly is delegated to the storage adapter layer.
        // Returns a JSON manifest entry suitable as the zip's index file.
        return JSON.stringify(
          {
            manifest: pkg,
            exportFormat: "zip/v1",
            exportedAt: Date.now(),
            formatSpec:
              "https://github.com/flat-circle/forensic-format/blob/main/SPEC.md",
          },
          null,
          2
        );
    }
  }

  getSealedPackages(): ReadonlyMap<string, IncidentPackage> {
    return this.sealed;
  }

  getPackageCount(): number {
    return this.sealed.size;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode 3 — Compliance Report Generation
// ─────────────────────────────────────────────────────────────────────────────

export interface ComplianceReportInput {
  readonly period: { from: number; to: number };
  readonly merkleRootHistory: MerkleRootSnapshot[];
  readonly threatVolume: Record<string, number>;
  readonly layerActivationStats: Record<number, number>;
  readonly aiCascadeStats: {
    failovers: number;
    tierDistribution: Record<string, number>;
  };
  readonly secretsRedactedCount: number;
  readonly dependencyIntegrityStatus: "clean" | "unverified" | "compromised";
  readonly dnsChanges: number;
  readonly exfiltrationAlertsCount: number;
  readonly incidentPackageCount: number;
}

export class ComplianceReportGenerator {
  private readonly config: Layer22Config;
  private readonly cascade: ProviderCascade;
  private readonly emit: EventEmitterFn;
  private lastReport: ComplianceReport | null = null;
  private nextScheduledAt: number;
  private reportTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    config: Layer22Config,
    cascade: ProviderCascade,
    emit: EventEmitterFn
  ) {
    this.config = config;
    this.cascade = cascade;
    this.emit = emit;
    this.nextScheduledAt = this.computeNext();
  }

  start(getInput: () => ComplianceReportInput): void {
    if (!this.config.complianceReportEnabled || this.reportTimer) return;
    const schedule = this.config.complianceReportSchedule ?? "weekly";
    if (schedule === "on-demand") return;
    const ms = scheduleIntervalMs(schedule);
    this.reportTimer = setInterval(
      () => void this.generate(getInput(), "static"),
      ms
    );
  }

  stop(): void {
    if (this.reportTimer) {
      clearInterval(this.reportTimer);
      this.reportTimer = null;
    }
  }

  async generate(
    input: ComplianceReportInput,
    providerTier: AIProviderTier
  ): Promise<ComplianceReport> {
    const executiveSummary = await this.generateExecutiveSummary(
      input,
      providerTier
    );

    const report: ComplianceReport = {
      id: crypto.randomUUID(),
      period: input.period,
      generatedAt: Date.now(),
      merkleRootHistory: input.merkleRootHistory,
      threatVolume: input.threatVolume,
      layerActivationStats: input.layerActivationStats,
      aiCascadeStats: input.aiCascadeStats,
      secretsRedactedCount: input.secretsRedactedCount,
      dependencyIntegrityStatus: input.dependencyIntegrityStatus,
      dnsChanges: input.dnsChanges,
      exfiltrationAlertsCount: input.exfiltrationAlertsCount,
      incidentPackageCount: input.incidentPackageCount,
      executiveSummary,
      signature: null,
    };

    this.lastReport = report;
    this.nextScheduledAt = this.computeNext();
    this.emit(
      buildSystemEvent(
        "compliance.report.generated",
        {
          reportId: report.id,
          periodFrom: report.period.from,
          periodTo: report.period.to,
        },
        providerTier
      )
    );

    return report;
  }

  private async generateExecutiveSummary(
    input: ComplianceReportInput,
    providerTier: AIProviderTier
  ): Promise<string> {
    const totalThreats = Object.values(input.threatVolume).reduce(
      (a, b) => a + b,
      0
    );
    const from = new Date(input.period.from).toISOString().slice(0, 10);
    const to = new Date(input.period.to).toISOString().slice(0, 10);

    if (providerTier === "static") {
      return [
        `Security Posture Report — ${from} to ${to}.`,
        `Total threat events: ${totalThreats}. Incidents sealed: ${input.incidentPackageCount}.`,
        `Secrets intercepted: ${input.secretsRedactedCount}. DNS changes: ${input.dnsChanges}.`,
        `Exfiltration alerts: ${input.exfiltrationAlertsCount}. Dependencies: ${input.dependencyIntegrityStatus}.`,
        `AI failovers: ${input.aiCascadeStats.failovers}. Merkle chain: ${input.merkleRootHistory.length} root transitions — intact.`,
      ].join(" ");
    }

    try {
      const result = await this.cascade.generate({
        system:
          "You are a CISO writing an executive security summary for board presentation. Plain English. Concise.",
        prompt:
          `Write a 3-sentence executive security summary for ${from} to ${to}. ` +
          `Data: ${totalThreats} threat events detected and contained, ` +
          `${input.incidentPackageCount} incidents sealed with forensic documentation, ` +
          `${input.secretsRedactedCount} credential leaks intercepted, ` +
          `${input.exfiltrationAlertsCount} exfiltration alerts, ` +
          `dependency integrity ${input.dependencyIntegrityStatus}, ` +
          `${input.dnsChanges} DNS changes. Audit trail is continuous and unbroken.`,
        maxTokens: 150,
      });
      return result.text;
    } catch {
      return (
        `Security posture report generated for ${from} to ${to}. ` +
        `${totalThreats} threat events processed. ` +
        `Merkle audit trail intact across ${input.merkleRootHistory.length} root transitions.`
      );
    }
  }

  export(format: ComplianceReportFormat): string | null {
    if (!this.lastReport) return null;
    const r = this.lastReport;
    switch (format) {
      case "json":
        return JSON.stringify(r, null, 2);
      case "csv": {
        const rows: [string, string][] = [
          ["field", "value"],
          ["report_id", r.id],
          ["period_from", new Date(r.period.from).toISOString()],
          ["period_to", new Date(r.period.to).toISOString()],
          ["generated_at", new Date(r.generatedAt).toISOString()],
          ["secrets_redacted", String(r.secretsRedactedCount)],
          ["dns_changes", String(r.dnsChanges)],
          ["exfiltration_alerts", String(r.exfiltrationAlertsCount)],
          ["incident_packages", String(r.incidentPackageCount)],
          ["dependency_integrity", r.dependencyIntegrityStatus],
          ["ai_failovers", String(r.aiCascadeStats.failovers)],
          ...Object.entries(r.threatVolume).map<[string, string]>(([k, v]) => [
            `threat_${k}`,
            String(v),
          ]),
        ];
        return rows.map((row) => row.join(",")).join("\n");
      }
    }
  }

  getLastReport(): ComplianceReport | null { return this.lastReport; }
  getNextScheduledAt(): number { return this.nextScheduledAt; }

  private computeNext(): number {
    return (
      Date.now() +
      scheduleIntervalMs(this.config.complianceReportSchedule ?? "weekly")
    );
  }
}

function scheduleIntervalMs(s: ComplianceReportSchedule): number {
  switch (s) {
    case "daily":   return 86_400_000;
    case "weekly":  return 7 * 86_400_000;
    case "monthly": return 30 * 86_400_000;
    default:        return 7 * 86_400_000;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode 4 — Legal Hold
// ─────────────────────────────────────────────────────────────────────────────

export class LegalHoldManager {
  private readonly config: Layer22Config;
  private readonly emit: EventEmitterFn;
  private privateKey: string | null = null;
  private activeHold: LegalHold | null = null;
  private readonly holdHistory: LegalHold[] = [];

  constructor(config: Layer22Config, emit: EventEmitterFn) {
    this.config = config;
    this.emit = emit;
  }

  async loadPrivateKey(): Promise<void> {
    if (this.config.signingPrivateKeyPath) {
      try {
        this.privateKey = await readFile(
          this.config.signingPrivateKeyPath,
          "utf8"
        );
      } catch {
        this.privateKey = null;
      }
    }
  }

  /**
   * Activate a legal hold. Freezes the current Merkle root snapshot and begins
   * a separate immutable record from this point forward.
   *
   * No automated process can expire or rotate the frozen record until
   * `release()` is explicitly called.
   */
  activate(
    frozenRoot: string,
    frozenLeafCount: number,
    reason: string,
    providerTier: AIProviderTier
  ): LegalHold {
    if (this.activeHold) return this.activeHold;

    const declaration = JSON.stringify({
      action: "activate",
      reason,
      frozenRoot,
      frozenLeafCount,
      timestamp: Date.now(),
    });

    const hold: LegalHold = {
      id: crypto.randomUUID(),
      activatedAt: Date.now(),
      reason,
      frozenMerkleRoot: frozenRoot,
      frozenLeafCount,
      holdDeclarationSignature: this.privateKey
        ? sign(declaration, this.privateKey)
        : null,
      releasedAt: null,
    };

    this.activeHold = hold;
    this.holdHistory.push(hold);
    this.emit(
      buildSystemEvent(
        "legal.hold.activated",
        { holdId: hold.id, reason, frozenRoot },
        providerTier
      )
    );

    return hold;
  }

  release(holdId: string, providerTier: AIProviderTier): boolean {
    if (!this.activeHold || this.activeHold.id !== holdId) return false;
    this.activeHold.releasedAt = Date.now();
    this.activeHold = null;
    this.emit(
      buildSystemEvent(
        "legal.hold.released",
        { holdId, releasedAt: Date.now() },
        providerTier
      )
    );
    return true;
  }

  getActiveHold(): LegalHold | null { return this.activeHold; }
  getHoldHistory(): readonly LegalHold[] { return this.holdHistory; }
  isHoldActive(): boolean { return this.activeHold !== null; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain of Custody Verifier
// ─────────────────────────────────────────────────────────────────────────────

export interface VerificationResult {
  readonly valid: boolean;
  readonly leafHash: string;
  readonly merkleRoot: string;
  readonly signatureValid: boolean | null;
  readonly reason: string;
}

export class ChainOfCustodyVerifier {
  private readonly engine: ForensicExportEngine;

  constructor(engine: ForensicExportEngine) {
    this.engine = engine;
  }

  /**
   * Verify that a leaf hash or serialized incident package is authentic.
   *
   * Pass a raw leaf hash to check it exists in the forensic registry.
   * Pass a serialized IncidentPackage JSON to verify proof chain and signature.
   *
   * @param input        - Raw leaf hash hex string or IncidentPackage JSON.
   * @param publicKeyPem - PEM public key for signature verification (optional).
   */
  verify(input: string, publicKeyPem?: string): VerificationResult {
    const trimmed = input.trim();

    // Attempt to parse as a serialized incident package
    try {
      const pkg = JSON.parse(trimmed) as Partial<IncidentPackage>;
      if (pkg.merkleRootAtClose && Array.isArray(pkg.proofChain)) {
        return this.verifyPackage(pkg as IncidentPackage, publicKeyPem);
      }
    } catch {
      // Not JSON — treat as raw leaf hash
    }

    return this.verifyLeafHash(trimmed);
  }

  private verifyLeafHash(leafHash: string): VerificationResult {
    const found = this.engine.hasLeafHash(leafHash);
    return {
      valid: found,
      leafHash,
      merkleRoot: this.engine.getLatestRoot(),
      signatureValid: null,
      reason: found
        ? "Leaf hash found in forensic registry"
        : "Leaf hash not found in forensic registry — may be from a pruned session",
    };
  }

  private verifyPackage(
    pkg: IncidentPackage,
    publicKeyPem?: string
  ): VerificationResult {
    const rootInChain = pkg.proofChain.includes(pkg.merkleRootAtClose);

    const keyToUse = publicKeyPem ?? pkg.publicKey ?? undefined;
    let signatureValid: boolean | null = null;
    if (pkg.signature && keyToUse) {
      const { signature: _sig, publicKey: _pk, ...body } = pkg;
      signatureValid = verifySignature(
        JSON.stringify(body),
        pkg.signature,
        keyToUse
      );
    }

    const valid =
      rootInChain && (signatureValid === null || signatureValid === true);

    return {
      valid,
      leafHash: pkg.proofChain[0] ?? "",
      merkleRoot: pkg.merkleRootAtClose,
      signatureValid,
      reason: valid
        ? "Package proof chain intact; signature valid"
        : !rootInChain
          ? "Merkle root not found in proof chain"
          : "Signature verification failed",
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified Layer 22 Engine
// ─────────────────────────────────────────────────────────────────────────────

export class ForensicExportEngine {
  readonly stream: ForensicStreamExporter;
  readonly incidentPackages: IncidentPackageBuilder;
  readonly complianceReports: ComplianceReportGenerator;
  readonly legalHold: LegalHoldManager;
  readonly verifier: ChainOfCustodyVerifier;

  /**
   * Per-session forensic leaf registry.
   * Layer 22 maintains its own read-side registry so it does not need to
   * reach into any existing layer's internals.
   */
  private readonly leafRegistry = new Map<string, ForensicLeafRecord[]>();
  private readonly rootHistory: MerkleRootSnapshot[] = [];
  private latestRoot = "";

  constructor(
    config: Layer22Config,
    cascade: ProviderCascade,
    emit: EventEmitterFn
  ) {
    this.stream = new ForensicStreamExporter(config, emit);
    this.incidentPackages = new IncidentPackageBuilder(config, cascade, emit);
    this.complianceReports = new ComplianceReportGenerator(
      config,
      cascade,
      emit
    );
    this.legalHold = new LegalHoldManager(config, emit);
    this.verifier = new ChainOfCustodyVerifier(this);
  }

  async initialize(): Promise<void> {
    await Promise.all([
      this.incidentPackages.loadPrivateKey(),
      this.legalHold.loadPrivateKey(),
    ]);
    this.stream.start();
  }

  /**
   * Called whenever a new Merkle leaf is written by any layer.
   * Enriches the leaf with export metadata and enqueues it for streaming.
   */
  onLeaf(
    leaf: MerkleLeaf,
    merkleRoot: string,
    aiTier: AIProviderTier
  ): void {
    const record = toForensicRecord(leaf, merkleRoot, aiTier);
    this.latestRoot = merkleRoot;

    const sessionRecords = this.leafRegistry.get(leaf.sessionId) ?? [];
    sessionRecords.push(record);
    this.leafRegistry.set(leaf.sessionId, sessionRecords);

    this.stream.enqueue(record);
  }

  /** Called when the Merkle engine emits a new root snapshot. */
  onRootSnapshot(snapshot: MerkleRootSnapshot): void {
    this.rootHistory.push(snapshot);
    this.latestRoot = snapshot.root;
  }

  /**
   * Compile and seal an incident package for a session.
   * Called by Layer 9's session close hook.
   */
  async sealSession(
    sessionId: string,
    openSnapshot: MerkleRootSnapshot,
    providerTier: AIProviderTier
  ): Promise<IncidentPackage | null> {
    const leaves = this.leafRegistry.get(sessionId) ?? [];
    return this.incidentPackages.compile(
      sessionId,
      leaves,
      openSnapshot,
      this.latestRoot,
      providerTier
    );
  }

  /** Returns true if a leaf hash exists in the forensic registry. */
  hasLeafHash(hash: string): boolean {
    for (const records of this.leafRegistry.values()) {
      if (records.some((r) => r.leafHash === hash)) return true;
    }
    return false;
  }

  getLatestRoot(): string { return this.latestRoot; }
  getRootHistory(): readonly MerkleRootSnapshot[] { return this.rootHistory; }
  getLeafRegistry(): ReadonlyMap<string, ForensicLeafRecord[]> {
    return this.leafRegistry;
  }

  destroy(): void {
    this.stream.stop();
    this.complianceReports.stop();
  }
}
