/**
 * Flat Circle — Modulo 7 Rhythm System
 *
 * Five independent clocks pulsing across layers 2, 5, 7, 10, and 11.
 * Each seeded differently. The system never obviously repeats.
 *
 * The attacker's timing is always wrong.
 */

import type { Mod7Clocks } from "./types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Prime-seeded hash — ensures decorrelation between clocks
// ─────────────────────────────────────────────────────────────────────────────

function fmix32(h: number): number {
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h >>> 0;
}

function hashU32(value: number, seed: number): number {
  return fmix32(value ^ seed);
}

/** djb2 string hash → u32 */
function strHash(s: string): number {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  }
  return h;
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-clock seed constants (first seven primes beyond 100)
// ─────────────────────────────────────────────────────────────────────────────

const PRIME_HONEYPOT = 101;
const PRIME_TEMPORAL = 103;
const PRIME_ENTROPY  = 107;
const PRIME_ROUTES   = 109;
const PRIME_MERKLE   = 113;

// ─────────────────────────────────────────────────────────────────────────────
// Clock derivation functions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Layer 2 — honeypot rotation clock.
 * Value: mod 7 of current hour, mixed with global seed.
 */
export function honeypotClock(globalSeed: string, now = Date.now()): number {
  const hour = Math.floor(now / 3_600_000) % 24;
  const mixed = hashU32(hour, strHash(globalSeed) ^ PRIME_HONEYPOT);
  return mixed % 7;
}

/**
 * Layer 5 — temporal gating clock.
 * Value: mod 7 of session-specific prime seed × current minute index.
 */
export function temporalClock(sessionId: string, globalSeed: string, now = Date.now()): number {
  const minuteIdx = Math.floor(now / 60_000);
  const sessionSeed = strHash(sessionId) ^ strHash(globalSeed) ^ PRIME_TEMPORAL;
  return hashU32(minuteIdx, sessionSeed) % 7;
}

/**
 * Layer 7 — entropy injection clock.
 * Value: mod 7 of session hash.
 */
export function entropyClock(sessionId: string, globalSeed: string): number {
  const h = hashU32(strHash(sessionId), strHash(globalSeed) ^ PRIME_ENTROPY);
  return h % 7;
}

/**
 * Layer 10 — route morphing clock.
 * Value: mod 7 of current day, mixed with global seed.
 */
export function routesClock(globalSeed: string, now = Date.now()): number {
  const day = Math.floor(now / 86_400_000);
  const mixed = hashU32(day, strHash(globalSeed) ^ PRIME_ROUTES);
  return mixed % 7;
}

/**
 * Layer 11 — Merkle verification clock.
 * Value: mod 7 of transaction count.
 */
export function merkleClock(transactionCount: number, globalSeed: string): number {
  const mixed = hashU32(transactionCount, strHash(globalSeed) ^ PRIME_MERKLE);
  return mixed % 7;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API: compute all five clocks in one call
// ─────────────────────────────────────────────────────────────────────────────

export interface Mod7ClockInput {
  sessionId: string;
  globalSeed: string;
  transactionCount: number;
  now?: number;
}

export function computeMod7Clocks(input: Mod7ClockInput): Mod7Clocks {
  const { sessionId, globalSeed, transactionCount, now = Date.now() } = input;
  return {
    honeypot: honeypotClock(globalSeed, now),
    temporal: temporalClock(sessionId, globalSeed, now),
    entropy:  entropyClock(sessionId, globalSeed),
    routes:   routesClock(globalSeed, now),
    merkle:   merkleClock(transactionCount, globalSeed),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Temporal gate validator (Layer 5)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the request timestamp satisfies the session-specific
 * mod 7 gate. A request is valid only when:
 *   (floor(timestamp / 60_000)) mod 7 === session-prime-seed mod 7
 */
export function validateTemporalGate(sessionId: string, globalSeed: string, now = Date.now()): boolean {
  const expected = temporalClock(sessionId, globalSeed, now);
  const actual   = Math.floor(now / 60_000) % 7;
  return expected === actual;
}

// ─────────────────────────────────────────────────────────────────────────────
// Active honeypot slot set (Layer 2)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Given a list of honeypot route indices, returns the subset that is active
 * in the current mod 7 cycle. Active slots are a deterministic but rotating
 * window keyed to the honeypot clock value.
 */
export function activeHoneypotSlots(
  allSlots: number[],
  clockValue: number,
  activeCount: number
): number[] {
  // Rotate the array by clockValue positions to select active window
  const rotated = [...allSlots.slice(clockValue), ...allSlots.slice(0, clockValue)];
  return rotated.slice(0, activeCount);
}

// ─────────────────────────────────────────────────────────────────────────────
// Ghost header count (Layer 7)
// ─────────────────────────────────────────────────────────────────────────────

export function ghostHeaderCount(base: number, entropyCycleClock: number): number {
  return base + entropyCycleClock * 2;
}
