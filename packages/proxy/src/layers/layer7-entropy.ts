/**
 * Layer 7 — Entropy Injection
 *
 * Outbound responses contain invisible noise — randomized ghost headers,
 * decoy JSON keys, phantom metadata fields.
 *
 * Ghost keys appear based on a mod 7 pattern seeded by session ID.
 * Each session gets a unique noise signature making cross-session
 * API modeling nearly impossible.
 */

import type { Layer7Config } from "@flat-circle/core/types";

const GHOST_HEADER_NAMES = [
  "x-cache", "x-cache-hits", "x-served-by", "x-timer",
  "x-request-uuid", "x-correlation-id", "x-trace-span",
  "x-edge-location", "x-backend-host", "x-lb-pool",
  "x-cdn-pop", "x-origin-hit", "x-age", "x-ttl",
  "x-cache-status", "x-datacenter", "x-replica-id",
];

const GHOST_JSON_KEYS = [
  "_rid", "_ts", "_etag", "_self", "_attachments",
  "_version", "_rev", "_seq", "_source", "_id",
  "_meta", "_links", "_embedded", "_pagination",
  "requestId", "traceId", "spanId", "correlationId",
  "_queryStats", "_serverTime", "_cacheHit", "_region",
];

function seededChoice<T>(arr: T[], seed: number, offset: number): T {
  return arr[(seed * 31 + offset) % arr.length]!;
}

function seededValue(seed: number, idx: number): string {
  const values = [
    crypto.randomUUID(),
    `HIT`,
    `MISS`,
    `${(seed + idx) % 3}`,
    `us-east-1`,
    `prod-lb-${(seed % 8) + 1}`,
    `${Date.now()}`,
    `0.001`,
    `${Math.floor(seed * 0.137) % 256}`,
    `true`,
  ];
  return values[(seed + idx * 7) % values.length]!;
}

function djb2Hash(s: string): number {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  }
  return h;
}

export function buildGhostHeaders(
  config: Layer7Config,
  sessionId: string,
  entropyClock: number
): Record<string, string> {
  if (!config.enabled) return {};
  const seed = djb2Hash(sessionId);
  const count = (config.ghostHeadersBase ?? 3) + entropyClock * 2;
  const headers: Record<string, string> = {};

  for (let i = 0; i < count; i++) {
    const name = seededChoice(GHOST_HEADER_NAMES, seed, i);
    const value = seededValue(seed, i);
    if (name) headers[name] = value;
  }
  return headers;
}

export function injectEntropy(
  body: string,
  entropyClock: number,
  sessionId: string,
  config: Layer7Config
): string {
  if (!config.enabled) return body;

  // Only inject into JSON responses
  const trimmed = body.trimStart();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return body;

  try {
    const seed = djb2Hash(sessionId);
    const keyCount = (config.ghostJsonKeysBase ?? 2) + (entropyClock % 3);
    const parsed = JSON.parse(body) as Record<string, unknown>;

    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return body;

    for (let i = 0; i < keyCount; i++) {
      const key = seededChoice(GHOST_JSON_KEYS, seed, i + entropyClock * 100);
      if (key && !(key in parsed)) {
        parsed[key] = seededValue(seed, i);
      }
    }

    return JSON.stringify(parsed);
  } catch {
    return body;
  }
}
