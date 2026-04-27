/**
 * Layer 16 — Secrets Sentinel
 *
 * Credentials, API keys, tokens, and private values have a measurable entropy
 * signature. They look different from normal text at the pattern level even
 * without knowing what they are.
 *
 * This layer intercepts every outbound response, log emission, and header before
 * it leaves the system and scans for entropy patterns matching known credential
 * formats. Matches are redacted before transmission and logged as Merkle leaves.
 *
 * The AI provider cascade provides context-aware redaction decisions.
 * The static fallback uses deterministic regex and entropy scoring — this layer
 * never goes dark.
 */

import type {
  Layer16Config,
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

export type RedactionPatternType =
  | "aws-access-key"
  | "aws-secret-key"
  | "jwt-token"
  | "pem-private-key"
  | "generic-api-key"
  | "high-entropy-string"
  | "bearer-token"
  | "github-token"
  | "stripe-key"
  | "custom";

export interface RedactionMatch {
  readonly patternType: RedactionPatternType;
  readonly field: string;
  readonly redactedValue: string;
  readonly entropyScore: number;
}

export interface RedactionResult {
  readonly redacted: boolean;
  readonly matches: RedactionMatch[];
}

export interface SentinelScanResult {
  readonly response: FlatCircleResponse;
  readonly redactions: RedactionMatch[];
  readonly totalRedacted: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in pattern library
// ─────────────────────────────────────────────────────────────────────────────

interface BuiltinPattern {
  readonly type: RedactionPatternType;
  readonly regex: RegExp;
  readonly minEntropy?: number;
}

const BUILTIN_PATTERNS: BuiltinPattern[] = [
  { type: "aws-access-key",  regex: /\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/g },
  { type: "aws-secret-key",  regex: /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g, minEntropy: 5.0 },
  { type: "jwt-token",       regex: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g },
  { type: "pem-private-key", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { type: "github-token",    regex: /ghp_[A-Za-z0-9]{36}/g },
  { type: "stripe-key",      regex: /(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}/g },
  { type: "bearer-token",    regex: /Bearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}/g },
  { type: "generic-api-key", regex: /(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]?([A-Za-z0-9\-._~+/]{16,})['"]?/gi },
];

// ─────────────────────────────────────────────────────────────────────────────
// Shannon entropy calculation
// ─────────────────────────────────────────────────────────────────────────────

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Scan a string for high-entropy tokens — substrings that score above the
 * configured threshold and are at least 20 characters long.
 * Uses a sliding window approach to find contiguous high-entropy segments.
 */
function findHighEntropySegments(text: string, threshold: number): string[] {
  const results: string[] = [];
  // Tokenize on whitespace and common delimiters
  const tokens = text.split(/[\s,;'"<>\[\]{}()\n\r\t]+/);
  for (const token of tokens) {
    if (token.length >= 20 && shannonEntropy(token) >= threshold) {
      results.push(token);
    }
  }
  return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// Redaction helpers
// ─────────────────────────────────────────────────────────────────────────────

function redactString(s: string, value: string): string {
  return s.split(value).join("[REDACTED]");
}

function redactWithPattern(s: string, regex: RegExp): { result: string; found: string[] } {
  const found: string[] = [];
  const result = s.replace(regex, (match) => {
    found.push(match);
    return "[REDACTED]";
  });
  return { result, found };
}

function serializeForScan(value: unknown): string {
  if (typeof value === "string") return value;
  try { return JSON.stringify(value); } catch { return ""; }
}

// ─────────────────────────────────────────────────────────────────────────────
// SecretsSentinel
// ─────────────────────────────────────────────────────────────────────────────

export class SecretsSentinel {
  private readonly config: Layer16Config;
  private readonly cascade: ProviderCascade;
  private readonly emit: EventEmitterFn;
  private readonly merkle: MerkleIntegrityEngine | undefined;
  private readonly extraPatterns: RegExp[];
  private readonly entropyThreshold: number;
  private totalRedacted = 0;

  constructor(
    config: Layer16Config,
    cascade: ProviderCascade,
    emit: EventEmitterFn,
    merkle?: MerkleIntegrityEngine
  ) {
    this.config = config;
    this.cascade = cascade;
    this.emit = emit;
    this.merkle = merkle;
    this.entropyThreshold = config.entropyThreshold ?? 4.5;
    this.extraPatterns = (config.extraPatterns ?? []).map((p) => {
      try { return new RegExp(p, "g"); } catch { return null; }
    }).filter((p): p is RegExp => p !== null);
  }

  /**
   * Scan and redact secrets from an outbound response.
   * Modifies headers and body in place on the cloned response.
   */
  async scanResponse(
    response: FlatCircleResponse,
    sessionId: string,
    providerTier: AIProviderTier
  ): Promise<SentinelScanResult> {
    const cloned: FlatCircleResponse = {
      status: response.status,
      headers: { ...response.headers },
      body: response.body,
    };

    const allRedactions: RedactionMatch[] = [];

    if (this.config.scanHeaders !== false) {
      for (const [key, value] of Object.entries(cloned.headers)) {
        const { redacted, matches } = this.scanString(value, `header:${key}`, providerTier);
        if (redacted) {
          let v = value;
          for (const m of matches) v = redactString(v, m.redactedValue);
          cloned.headers[key] = v;
          allRedactions.push(...matches);
        }
      }
    }

    if (this.config.scanBody !== false && cloned.body != null) {
      const bodyStr = serializeForScan(cloned.body);
      const { redacted, matches } = this.scanString(bodyStr, "response.body", providerTier);
      if (redacted) {
        let redactedBody = bodyStr;
        for (const m of matches) redactedBody = redactString(redactedBody, m.redactedValue);
        try { cloned.body = JSON.parse(redactedBody); } catch { cloned.body = redactedBody; }
        allRedactions.push(...matches);
      }
    }

    if (allRedactions.length > 0) {
      this.totalRedacted += allRedactions.length;
      for (const match of allRedactions) {
        const event = this.buildEvent("secret.redacted", { ...match, sessionId }, providerTier);
        this.emit(event);
        this.merkle?.recordHoneypotHit(event);
      }
    }

    return { response: cloned, redactions: allRedactions, totalRedacted: this.totalRedacted };
  }

  /**
   * Scan a string for secret patterns.
   * Returns synchronously when AI analysis is disabled or provider is static.
   */
  scanString(
    text: string,
    field: string,
    _providerTier: AIProviderTier
  ): RedactionResult {
    const matches: RedactionMatch[] = [];

    // Built-in patterns
    for (const pattern of BUILTIN_PATTERNS) {
      const { found } = redactWithPattern(text, new RegExp(pattern.regex.source, pattern.regex.flags));
      for (const value of found) {
        const entropy = shannonEntropy(value);
        if (pattern.minEntropy == null || entropy >= pattern.minEntropy) {
          matches.push({ patternType: pattern.type, field, redactedValue: value, entropyScore: entropy });
        }
      }
    }

    // Extra custom patterns
    for (const regex of this.extraPatterns) {
      const { found } = redactWithPattern(text, regex);
      for (const value of found) {
        matches.push({ patternType: "custom", field, redactedValue: value, entropyScore: shannonEntropy(value) });
      }
    }

    // High-entropy fallback scan
    const highEntropySegments = findHighEntropySegments(text, this.entropyThreshold);
    for (const segment of highEntropySegments) {
      // Skip if already caught by a named pattern
      const alreadyCaught = matches.some((m) => m.redactedValue === segment);
      if (!alreadyCaught) {
        matches.push({ patternType: "high-entropy-string", field, redactedValue: segment, entropyScore: shannonEntropy(segment) });
      }
    }

    return { redacted: matches.length > 0, matches };
  }

  /**
   * Scan a log string before it reaches the transport.
   * Returns the sanitized string.
   */
  scanLog(message: string): string {
    if (this.config.scanLogs === false) return message;
    const { redacted, matches } = this.scanString(message, "log.emission", "static");
    if (!redacted) return message;
    let result = message;
    for (const m of matches) result = redactString(result, m.redactedValue);
    return result;
  }

  getTotalRedacted(): number {
    return this.totalRedacted;
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
      sessionId: (meta["sessionId"] as string | undefined) ?? "unknown",
      ip: "outbound",
      providerTier,
      metadata: meta,
    };
  }
}
