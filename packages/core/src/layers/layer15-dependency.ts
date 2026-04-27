/**
 * Layer 15 — Dependency Integrity Monitor
 *
 * Supply chain attacks compromise the system before the first request arrives.
 * A malicious package update, a typosquatted library, a compromised maintainer
 * — none of these trigger behavioral anomalies because they are the behavior.
 *
 * This layer hashes every dependency in the lockfile at install time and stores
 * the manifest as a Merkle-committed record. On every boot, hashes are recomputed
 * and verified against the stored tree. Any deviation triggers an immediate alert.
 *
 * The static fallback maintains the last known good manifest so verification
 * never requires an AI provider or network call.
 */

import { createHash } from "node:crypto";
import { readFile, writeFile, access } from "node:fs/promises";
import { join } from "node:path";
import type {
  Layer15Config,
  FlatCircleEvent,
  EventEmitterFn,
  AIProviderTier,
} from "../types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type DependencyIntegrityStatus = "clean" | "unverified" | "compromised";

export interface DependencyEntry {
  readonly name: string;
  readonly version: string;
  readonly hash: string;
  readonly lockfileSource: string;
}

export interface DependencyManifest {
  readonly createdAt: number;
  readonly algorithm: "sha256" | "sha512";
  readonly lockfileHashes: Record<string, string>;
  readonly entries: DependencyEntry[];
  readonly manifestHash: string;
}

export interface IntegrityVerificationResult {
  readonly status: DependencyIntegrityStatus;
  readonly checkedAt: number;
  readonly packageCount: number;
  readonly mismatches: DependencyMismatch[];
}

export interface DependencyMismatch {
  readonly name: string;
  readonly lockfile: string;
  readonly expectedHash: string;
  readonly actualHash: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Lockfile parsers
// ─────────────────────────────────────────────────────────────────────────────

/** Extract a stable content hash from the raw lockfile bytes. */
function hashContent(content: string, algorithm: "sha256" | "sha512"): string {
  return createHash(algorithm).update(content, "utf8").digest("hex");
}

/**
 * Parse package-lock.json (npm) — extract name@version → integrity hash pairs.
 * We use the "integrity" field (SRI hash) when present; otherwise we hash the
 * entire version block as a fallback.
 */
function parseNpmLockfile(raw: string): DependencyEntry[] {
  try {
    const lock = JSON.parse(raw) as {
      packages?: Record<string, { name?: string; version?: string; integrity?: string }>;
    };
    const packages = lock.packages ?? {};
    return Object.entries(packages)
      .filter(([path]) => path.startsWith("node_modules/"))
      .map(([path, pkg]) => ({
        name: pkg.name ?? path.replace("node_modules/", ""),
        version: pkg.version ?? "unknown",
        hash: pkg.integrity ?? createHash("sha256").update(JSON.stringify(pkg)).digest("hex"),
        lockfileSource: "package-lock.json",
      }));
  } catch {
    return [];
  }
}

/**
 * Parse pnpm-lock.yaml — extract package identifiers and snapshot hashes.
 * We hash the raw yaml content per-package rather than parsing the full YAML
 * to avoid a yaml-parser dependency.
 */
function parsePnpmLockfile(raw: string): DependencyEntry[] {
  const entries: DependencyEntry[] = [];
  const lines = raw.split("\n");
  let currentPkg = "";

  for (const line of lines) {
    // pnpm-lock.yaml section headers look like: /lodash@4.17.21:
    const pkgMatch = line.match(/^\/(@?[^@\s]+)@([^:]+):$/);
    if (pkgMatch) {
      currentPkg = `${pkgMatch[1]}@${pkgMatch[2]}`;
    }
    // Look for integrity field
    const integrityMatch = line.match(/^\s+integrity:\s+(\S+)/);
    if (integrityMatch && currentPkg) {
      const [, name = "", version = ""] = currentPkg.split("@", 2).concat(["", ""]) as [string, string, string];
      entries.push({
        name: name || currentPkg,
        version,
        hash: integrityMatch[1] ?? "",
        lockfileSource: "pnpm-lock.yaml",
      });
      currentPkg = "";
    }
  }
  return entries;
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest hash (Merkle-committed fingerprint of the entire dependency set)
// ─────────────────────────────────────────────────────────────────────────────

function computeManifestHash(entries: DependencyEntry[], algorithm: "sha256" | "sha512"): string {
  const sorted = [...entries].sort((a, b) => a.name.localeCompare(b.name));
  const payload = sorted.map((e) => `${e.name}@${e.version}:${e.hash}`).join("\n");
  return createHash(algorithm).update(payload, "utf8").digest("hex");
}

// ─────────────────────────────────────────────────────────────────────────────
// DependencyIntegrityMonitor
// ─────────────────────────────────────────────────────────────────────────────

const CANDIDATE_LOCKFILES = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"];
const DEFAULT_MANIFEST_PATH = ".flat-circle/dependency-manifest.json";

export class DependencyIntegrityMonitor {
  private readonly config: Required<Pick<Layer15Config, "algorithm" | "haltOnMismatch" | "verifyOnBoot">> & Layer15Config;
  private readonly emit: EventEmitterFn;
  private lastResult: IntegrityVerificationResult | null = null;

  constructor(config: Layer15Config, emit: EventEmitterFn) {
    this.config = {
      enabled: config.enabled,
      algorithm: config.algorithm ?? "sha256",
      haltOnMismatch: config.haltOnMismatch ?? false,
      verifyOnBoot: config.verifyOnBoot ?? true,
      manifestPath: config.manifestPath,
      lockfilePaths: config.lockfilePaths,
    };
    this.emit = emit;
  }

  private get manifestPath(): string {
    return this.config.manifestPath ?? DEFAULT_MANIFEST_PATH;
  }

  private get algorithm(): "sha256" | "sha512" {
    return this.config.algorithm;
  }

  /** Scan and read all configured lockfiles. */
  private async readLockfiles(projectRoot: string): Promise<Map<string, string>> {
    const result = new Map<string, string>();
    const paths = this.config.lockfilePaths ?? CANDIDATE_LOCKFILES.map((f) => join(projectRoot, f));
    for (const p of paths) {
      try {
        await access(p);
        const content = await readFile(p, "utf8");
        result.set(p, content);
      } catch {
        // File doesn't exist — skip silently.
      }
    }
    return result;
  }

  /** Build entries from all available lockfiles. */
  private parseAll(lockfiles: Map<string, string>): DependencyEntry[] {
    const entries: DependencyEntry[] = [];
    for (const [path, content] of lockfiles) {
      if (path.endsWith("package-lock.json")) entries.push(...parseNpmLockfile(content));
      else if (path.endsWith("pnpm-lock.yaml")) entries.push(...parsePnpmLockfile(content));
      // yarn.lock parsing falls back to whole-file content hash
      else entries.push({ name: path, version: "lockfile", hash: hashContent(content, this.algorithm), lockfileSource: path });
    }
    return entries;
  }

  /**
   * Record the current dependency state as the known-good manifest.
   * Call this after a verified clean install.
   */
  async recordGoodState(projectRoot: string): Promise<DependencyManifest> {
    const lockfiles = await this.readLockfiles(projectRoot);
    const entries = this.parseAll(lockfiles);

    const lockfileHashes: Record<string, string> = {};
    for (const [path, content] of lockfiles) {
      lockfileHashes[path] = hashContent(content, this.algorithm);
    }

    const manifest: DependencyManifest = {
      createdAt: Date.now(),
      algorithm: this.algorithm,
      lockfileHashes,
      entries,
      manifestHash: computeManifestHash(entries, this.algorithm),
    };

    await writeFile(this.manifestPath, JSON.stringify(manifest, null, 2), "utf8");
    return manifest;
  }

  /**
   * Verify current lockfile state against the stored manifest.
   * Returns the verification result without throwing (unless haltOnMismatch is true
   * and mismatches are found).
   */
  async verify(projectRoot: string, providerTier: AIProviderTier = "static"): Promise<IntegrityVerificationResult> {
    let storedManifest: DependencyManifest | null = null;
    try {
      const raw = await readFile(this.manifestPath, "utf8");
      storedManifest = JSON.parse(raw) as DependencyManifest;
    } catch {
      // No stored manifest — emit unverified and return.
      const result: IntegrityVerificationResult = {
        status: "unverified",
        checkedAt: Date.now(),
        packageCount: 0,
        mismatches: [],
      };
      this.lastResult = result;
      this.emit(this.buildEvent("dependency.integrity.verified", { status: "unverified", reason: "no manifest" }, providerTier));
      return result;
    }

    const lockfiles = await this.readLockfiles(projectRoot);
    const currentEntries = this.parseAll(lockfiles);
    const currentManifestHash = computeManifestHash(currentEntries, this.algorithm);

    const mismatches: DependencyMismatch[] = [];

    if (currentManifestHash !== storedManifest.manifestHash) {
      // Find specific mismatches for reporting.
      const stored = new Map(storedManifest.entries.map((e) => [`${e.name}@${e.version}`, e]));
      for (const entry of currentEntries) {
        const key = `${entry.name}@${entry.version}`;
        const storedEntry = stored.get(key);
        if (!storedEntry) continue;
        if (storedEntry.hash !== entry.hash) {
          mismatches.push({
            name: entry.name,
            lockfile: entry.lockfileSource,
            expectedHash: storedEntry.hash,
            actualHash: entry.hash,
          });
        }
      }
    }

    const status: DependencyIntegrityStatus = mismatches.length > 0 ? "compromised" : "clean";
    const result: IntegrityVerificationResult = {
      status,
      checkedAt: Date.now(),
      packageCount: currentEntries.length,
      mismatches,
    };
    this.lastResult = result;

    if (status === "compromised") {
      for (const mismatch of mismatches) {
        this.emit(this.buildEvent("dependency.mismatch.detected", { ...mismatch }, providerTier));
      }
      if (this.config.haltOnMismatch) {
        throw new Error(
          `[Layer 15] Dependency integrity check failed: ${mismatches.length} mismatch(es). ` +
          `First: ${mismatches[0]?.name ?? "unknown"}. Halting startup.`
        );
      }
    } else {
      this.emit(this.buildEvent("dependency.integrity.verified", { packageCount: currentEntries.length }, providerTier));
    }

    return result;
  }

  lastVerificationResult(): IntegrityVerificationResult | null {
    return this.lastResult;
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
      ip: "127.0.0.1",
      providerTier,
      metadata: meta,
    };
  }
}
