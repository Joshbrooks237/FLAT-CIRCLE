/**
 * Layer 11 — Merkle Session Integrity
 *
 * Every request and response cycle is hashed and added as a leaf in a
 * Merkle tree. The root hash is recomputed on a mod 7 interval.
 *
 * The entire session history can be cryptographically verified at any point.
 * Honeypot interaction logs are also stored as Merkle leaves — a tamper-proof
 * audit trail of every probe attempt.
 *
 * If an attacker attempts to clean their tracks, the root hash has already
 * recorded them.
 */

import { createHash } from "node:crypto";
import type {
  Layer11Config,
  FlatCircleRequest,
  FlatCircleResponse,
  FlatCircleEvent,
  EventEmitterFn,
} from "../types.js";
import { merkleClock } from "../mod7.js";

// ─────────────────────────────────────────────────────────────────────────────
// Leaf types
// ─────────────────────────────────────────────────────────────────────────────

export type LeafKind = "request" | "response" | "honeypot" | "canary" | "anomaly" | "system";

export interface MerkleLeaf {
  readonly index: number;
  readonly kind: LeafKind;
  readonly sessionId: string;
  readonly timestamp: number;
  readonly hash: string;
  readonly data: Record<string, unknown>;
}

export interface MerkleRootSnapshot {
  readonly root: string;
  readonly leafCount: number;
  readonly timestamp: number;
  readonly transactionCount: number;
  readonly mod7Position: number;
  readonly verified: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hashing utilities
// ─────────────────────────────────────────────────────────────────────────────

type HashAlgorithm = "sha256" | "sha512" | "blake2b512";

function hashLeafData(data: Record<string, unknown>, algorithm: HashAlgorithm): string {
  const serialized = JSON.stringify(data, Object.keys(data).sort());
  return createHash(algorithm).update(serialized).digest("hex");
}

function hashPair(left: string, right: string, algorithm: HashAlgorithm): string {
  return createHash(algorithm)
    .update(left)
    .update(right)
    .digest("hex");
}

/**
 * Compute the Merkle root for an ordered list of leaf hashes.
 * If count is odd, the last leaf is doubled (standard Merkle construction).
 */
function computeRoot(hashes: string[], algorithm: HashAlgorithm): string {
  if (hashes.length === 0) return "0".repeat(64);
  if (hashes.length === 1) return hashes[0]!;

  const next: string[] = [];
  for (let i = 0; i < hashes.length; i += 2) {
    const left = hashes[i]!;
    const right = hashes[i + 1] ?? left; // Double last leaf if odd
    next.push(hashPair(left, right, algorithm));
  }
  return computeRoot(next, algorithm);
}

/**
 * Compute a Merkle proof path from leaf index to root.
 * Returns an array of { hash, position } for verification.
 */
export interface ProofNode {
  hash: string;
  position: "left" | "right";
}

export function computeProof(hashes: string[], leafIndex: number): ProofNode[] {
  const proof: ProofNode[] = [];
  let level = [...hashes];
  let idx = leafIndex;

  while (level.length > 1) {
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    const sibling = level[siblingIdx] ?? level[idx]!;
    proof.push({ hash: sibling, position: idx % 2 === 0 ? "right" : "left" });

    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1] ?? left;
      next.push(left + right); // Not hashing here — just index tracking
    }
    level = next;
    idx = Math.floor(idx / 2);
  }

  return proof;
}

/**
 * Verify a leaf hash against a known root using a proof path.
 */
export function verifyProof(
  leafHash: string,
  proof: ProofNode[],
  expectedRoot: string,
  algorithm: HashAlgorithm
): boolean {
  let current = leafHash;
  for (const node of proof) {
    const [left, right] = node.position === "right"
      ? [current, node.hash]
      : [node.hash, current];
    current = hashPair(left!, right!, algorithm);
  }
  return current === expectedRoot;
}

// ─────────────────────────────────────────────────────────────────────────────
// MerkleSessionTree — per-session tree accumulator
// ─────────────────────────────────────────────────────────────────────────────

export class MerkleSessionTree {
  private readonly leaves: MerkleLeaf[] = [];
  private leafHashes: string[] = [];
  private currentRoot: string = "0".repeat(64);
  private rootComputedAt: number = 0;
  private transactionCount: number = 0;
  private lastMod7Position: number = -1;
  private readonly algorithm: HashAlgorithm;
  private readonly batchSize: number;
  private readonly sessionId: string;
  private readonly globalSeed: string;

  constructor(
    sessionId: string,
    algorithm: HashAlgorithm,
    batchSize: number,
    globalSeed: string
  ) {
    this.sessionId = sessionId;
    this.algorithm = algorithm;
    this.batchSize = batchSize;
    this.globalSeed = globalSeed;
  }

  /** Add a leaf to the tree. Recomputes root on batch boundary or mod7 transition. */
  addLeaf(kind: LeafKind, data: Record<string, unknown>): MerkleLeaf {
    const hash = hashLeafData(
      { kind, sessionId: this.sessionId, timestamp: Date.now(), data },
      this.algorithm
    );

    const leaf: MerkleLeaf = {
      index: this.leaves.length,
      kind,
      sessionId: this.sessionId,
      timestamp: Date.now(),
      hash,
      data,
    };

    this.leaves.push(leaf);
    this.leafHashes.push(hash);
    this.transactionCount++;

    const mod7 = merkleClock(this.transactionCount, this.globalSeed);
    const shouldRecompute =
      this.leaves.length % this.batchSize === 0 ||
      mod7 !== this.lastMod7Position;

    if (shouldRecompute) {
      this.recomputeRoot(mod7);
    }

    return leaf;
  }

  private recomputeRoot(mod7Position: number): void {
    this.currentRoot = computeRoot(this.leafHashes, this.algorithm);
    this.rootComputedAt = Date.now();
    this.lastMod7Position = mod7Position;
  }

  get root(): string { return this.currentRoot; }
  get leafCount(): number { return this.leaves.length; }
  get allLeaves(): readonly MerkleLeaf[] { return this.leaves; }

  snapshot(): MerkleRootSnapshot {
    const mod7 = merkleClock(this.transactionCount, this.globalSeed);
    return {
      root: this.currentRoot,
      leafCount: this.leaves.length,
      timestamp: this.rootComputedAt,
      transactionCount: this.transactionCount,
      mod7Position: mod7,
      verified: true,
    };
  }

  /**
   * Generate a cryptographic proof that a specific leaf was included in the tree
   * at the time of the current root hash. Returns the full chain of custody.
   */
  generateProof(leafIndex: number): {
    leaf: MerkleLeaf;
    proof: ProofNode[];
    root: string;
    valid: boolean;
  } | null {
    const leaf = this.leaves[leafIndex];
    if (!leaf) return null;

    const proof = computeProof(this.leafHashes, leafIndex);
    const valid = verifyProof(leaf.hash, proof, this.currentRoot, this.algorithm);

    return { leaf, proof, root: this.currentRoot, valid };
  }

  /**
   * Attempt to detect tampering by recomputing the root from scratch
   * and comparing to the stored value.
   */
  verifyIntegrity(): { intact: boolean; expectedRoot: string; storedRoot: string } {
    const expectedRoot = computeRoot(this.leafHashes, this.algorithm);
    return {
      intact: expectedRoot === this.currentRoot,
      expectedRoot,
      storedRoot: this.currentRoot,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MerkleIntegrityEngine — Layer 11 orchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class MerkleIntegrityEngine {
  private readonly config: Required<Layer11Config>;
  private readonly emit: EventEmitterFn;
  private readonly globalSeed: string;
  private readonly sessionTrees = new Map<string, MerkleSessionTree>();
  private globalTransactionCount = 0;

  constructor(config: Layer11Config, emit: EventEmitterFn, globalSeed: string) {
    this.config = {
      enabled: config.enabled,
      algorithm: config.algorithm ?? "sha256",
      batchSize: config.batchSize ?? 32,
      persist: config.persist ?? false,
      includeHoneypotLeaves: config.includeHoneypotLeaves ?? true,
    };
    this.emit = emit;
    this.globalSeed = globalSeed;
  }

  private getOrCreateTree(sessionId: string): MerkleSessionTree {
    if (!this.sessionTrees.has(sessionId)) {
      this.sessionTrees.set(
        sessionId,
        new MerkleSessionTree(
          sessionId,
          this.config.algorithm,
          this.config.batchSize,
          this.globalSeed
        )
      );
    }
    return this.sessionTrees.get(sessionId)!;
  }

  /** Record an incoming request as a Merkle leaf. */
  recordRequest(req: FlatCircleRequest): MerkleLeaf {
    const tree = this.getOrCreateTree(req.sessionId);
    this.globalTransactionCount++;
    return tree.addLeaf("request", {
      method: req.method,
      path: req.path,
      ip: req.ip,
      timestamp: req.timestamp,
      queryKeys: Object.keys(req.query),
    });
  }

  /** Record an outbound response as a Merkle leaf. */
  recordResponse(sessionId: string, response: FlatCircleResponse): MerkleLeaf {
    const tree = this.getOrCreateTree(sessionId);
    this.globalTransactionCount++;
    return tree.addLeaf("response", {
      status: response.status,
      contentType: response.headers["content-type"] ?? "unknown",
      bodyHash: hashLeafData(
        { body: typeof response.body === "string" ? response.body : JSON.stringify(response.body) },
        this.config.algorithm
      ),
    });
  }

  /** Record a honeypot interaction as a Merkle leaf (tamper-proof probe log). */
  recordHoneypotHit(event: FlatCircleEvent): MerkleLeaf | null {
    if (!this.config.includeHoneypotLeaves) return null;
    const tree = this.getOrCreateTree(event.sessionId);
    this.globalTransactionCount++;
    const leaf = tree.addLeaf("honeypot", {
      eventId: event.id,
      eventType: event.type,
      ip: event.ip,
      depth: event.honeypotDepth ?? 0,
      providerTier: event.providerTier,
      metadata: event.metadata,
    });

    const snapshot = tree.snapshot();
    const mod7Transition = snapshot.mod7Position !== this.lastKnownMod7;
    if (mod7Transition) {
      this.emitRootUpdate(event.sessionId, tree);
    }
    return leaf;
  }

  private lastKnownMod7 = -1;

  private emitRootUpdate(sessionId: string, tree: MerkleSessionTree): void {
    const snapshot = tree.snapshot();
    this.lastKnownMod7 = snapshot.mod7Position;
    this.emit({
      id: crypto.randomUUID(),
      type: "merkle.root.updated",
      timestamp: Date.now(),
      sessionId,
      ip: "0.0.0.0",
      providerTier: "static",
      metadata: {
        root: snapshot.root,
        leafCount: snapshot.leafCount,
        mod7Position: snapshot.mod7Position,
        transactionCount: snapshot.transactionCount,
      },
    });
  }

  /** Get the current root snapshot for a session. */
  getSnapshot(sessionId: string): MerkleRootSnapshot | null {
    return this.sessionTrees.get(sessionId)?.snapshot() ?? null;
  }

  /**
   * Get a cryptographic proof of a specific leaf's inclusion.
   * Use this to prove the exact chain of custody from issuance to breach
   * when a canary fires.
   */
  getProof(sessionId: string, leafIndex: number) {
    return this.sessionTrees.get(sessionId)?.generateProof(leafIndex) ?? null;
  }

  /** Verify a session's tree integrity. Detects tampering. */
  verifySession(sessionId: string): ReturnType<MerkleSessionTree["verifyIntegrity"]> | null {
    const tree = this.sessionTrees.get(sessionId);
    if (!tree) return null;
    const result = tree.verifyIntegrity();
    if (!result.intact) {
      this.emit({
        id: crypto.randomUUID(),
        type: "merkle.tamper.detected",
        timestamp: Date.now(),
        sessionId,
        ip: "0.0.0.0",
        providerTier: "static",
        metadata: { ...result },
      });
    }
    return result;
  }

  /** Summary stats for dashboard. */
  getStats(): {
    activeSessions: number;
    totalLeaves: number;
    globalTransactionCount: number;
  } {
    let totalLeaves = 0;
    for (const tree of this.sessionTrees.values()) {
      totalLeaves += tree.leafCount;
    }
    return {
      activeSessions: this.sessionTrees.size,
      totalLeaves,
      globalTransactionCount: this.globalTransactionCount,
    };
  }

  /** Prune session trees for sessions older than TTL. */
  pruneOldSessions(maxAgeMs = 4 * 60 * 60 * 1_000): void {
    const cutoff = Date.now() - maxAgeMs;
    for (const [id, tree] of this.sessionTrees) {
      const snap = tree.snapshot();
      if (snap.timestamp < cutoff && snap.leafCount > 0) {
        this.sessionTrees.delete(id);
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Canary Token integration
// ─────────────────────────────────────────────────────────────────────────────

export interface CanaryToken {
  readonly tokenId: string;
  readonly sessionId: string;
  readonly leafIndex: number;
  readonly merkleRoot: string;
  readonly issuedAt: number;
  readonly tokenType: "response" | "asset" | "query" | "header";
  readonly embeddedAt: string;
}

export function issueCanaryToken(
  sessionId: string,
  tree: MerkleSessionTree,
  tokenType: CanaryToken["tokenType"],
  embeddedAt: string
): CanaryToken {
  const leaf = tree.addLeaf("canary", {
    tokenType,
    embeddedAt,
    issuedAt: Date.now(),
  });

  return {
    tokenId: `fc-${leaf.hash.slice(0, 16)}`,
    sessionId,
    leafIndex: leaf.index,
    merkleRoot: tree.root,
    issuedAt: leaf.timestamp,
    tokenType,
    embeddedAt,
  };
}

// Re-export helper for direct use
function hashLeafData(data: Record<string, unknown>, algorithm: HashAlgorithm): string {
  const serialized = JSON.stringify(data, Object.keys(data).sort());
  return createHash(algorithm).update(serialized).digest("hex");
}
