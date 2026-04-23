/**
 * Layer 2 — Honeypot Mesh with Modulo 7 Rotation and AI-Generated Decoys
 *
 * On initialization, Flat Circle scans the app's existing route structure
 * and auto-generates a shadow route layer — plausible but fake endpoints
 * derived from real ones.
 *
 * Which honeypot routes are active rotates on a mod 7 cycle keyed to the
 * current hour. When a probe hits an active honeypot, the AI provider stack
 * generates a dynamic, convincing decoy response tailored to whatever stack
 * the attacker's request fingerprint suggests they expect.
 *
 * Real routes are never exposed in error messages, headers, or stack traces.
 */

import type {
  Layer2Config,
  FlatCircleRequest,
  FlatCircleResponse,
  FlatCircleEvent,
  EventEmitterFn,
  HoneypotRoute,
  HttpMethod,
} from "../types.js";
import type { ProviderCascade } from "../provider-cascade.js";
import { activeHoneypotSlots, honeypotClock } from "../mod7.js";

// ─────────────────────────────────────────────────────────────────────────────
// Route generation — derives plausible shadow routes from real ones
// ─────────────────────────────────────────────────────────────────────────────

const DECOY_SEGMENTS = [
  "admin", "api", "internal", "v2", "v3", "v4", "legacy",
  "management", "control", "panel", "console", "dashboard",
  "config", "settings", "debug", "health", "metrics", "status",
  "users", "accounts", "auth", "login", "logout", "session",
  "data", "export", "import", "backup", "restore",
  "webhook", "callback", "notify", "events",
  "secret", "token", "key", "credential", "vault",
  "db", "database", "query", "schema", "migrate",
];

const DECOY_SUFFIXES = [
  "/list", "/all", "/export", "/dump", "/raw",
  "/details", "/info", "/meta", "/schema",
  "?debug=true", "?format=json", "?include_deleted=1",
  "/.env", "/config.json", "/secrets.json",
];

const METHOD_MAP: Record<string, HttpMethod> = {
  GET: "GET", POST: "POST", PUT: "PUT",
  PATCH: "PATCH", DELETE: "DELETE",
};

function deriveDecoyPaths(realPaths: string[], ratio: number, seed: string): HoneypotRoute[] {
  const routes: HoneypotRoute[] = [];
  const seedHash = djb2Hash(seed);

  for (const real of realPaths) {
    const segments = real.split("/").filter(Boolean);

    for (let i = 0; i < ratio; i++) {
      const segIdx = (seedHash + i + routes.length) % DECOY_SEGMENTS.length;
      const suffixIdx = (seedHash * 3 + i) % DECOY_SUFFIXES.length;
      const segment = DECOY_SEGMENTS[segIdx]!;
      const suffix = DECOY_SUFFIXES[suffixIdx]!;

      // Mutate a segment or append to the real path
      const mutated = segments.length > 0
        ? [...segments.slice(0, -1), segment].join("/")
        : segment;

      routes.push({
        path: `/${mutated}${suffix.startsWith("?") ? "" : ""}${suffix.startsWith("?") ? real + suffix : suffix}`,
        method: "ANY",
        decoyType: inferDecoyType(segment),
      });
    }
  }

  // Add universal high-value honeypots
  const universalHoneypots: HoneypotRoute[] = [
    { path: "/.env", method: "GET", decoyType: "config" },
    { path: "/admin", method: "ANY", decoyType: "admin" },
    { path: "/api/v1/admin/users", method: "GET", decoyType: "data" },
    { path: "/wp-admin", method: "ANY", decoyType: "admin" },
    { path: "/phpmyadmin", method: "ANY", decoyType: "admin" },
    { path: "/.git/config", method: "GET", decoyType: "config" },
    { path: "/config.yml", method: "GET", decoyType: "config" },
    { path: "/api/internal/credentials", method: "GET", decoyType: "auth" },
    { path: "/v1/secrets", method: "GET", decoyType: "auth" },
    { path: "/actuator/env", method: "GET", decoyType: "config" },
  ];

  return [...routes, ...universalHoneypots];
}

function inferDecoyType(segment: string): HoneypotRoute["decoyType"] {
  if (["admin", "panel", "console", "dashboard", "management"].includes(segment)) return "admin";
  if (["auth", "login", "session", "token", "credential", "secret", "key", "vault"].includes(segment)) return "auth";
  if (["data", "export", "backup", "db", "database", "query", "dump"].includes(segment)) return "data";
  if (["config", "settings", "env", "secret", "schema"].includes(segment)) return "config";
  if (["health", "metrics", "status", "debug"].includes(segment)) return "health";
  return "api";
}

function djb2Hash(s: string): number {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  }
  return h;
}

// ─────────────────────────────────────────────────────────────────────────────
// Fingerprint detection — infers what stack the attacker expects to find
// ─────────────────────────────────────────────────────────────────────────────

type StackFingerprint = "node" | "php" | "python" | "java" | "dotnet" | "ruby" | "generic";

function detectExpectedStack(req: FlatCircleRequest): StackFingerprint {
  const ua = (req.headers["user-agent"] ?? "").toLowerCase();
  const path = req.path.toLowerCase();
  const accept = (req.headers["accept"] ?? "").toLowerCase();

  if (path.includes(".php") || path.includes("wp-") || accept.includes("text/html")) return "php";
  if (path.includes("/actuator") || path.includes("/spring") || ua.includes("java")) return "java";
  if (path.includes(".aspx") || path.includes("/api/odata") || ua.includes(".net")) return "dotnet";
  if (path.includes("django") || path.includes("/python") || ua.includes("python")) return "python";
  if (path.includes(".rb") || path.includes("/rails")) return "ruby";
  if (ua.includes("node") || path.includes("/api/")) return "node";
  return "generic";
}

// ─────────────────────────────────────────────────────────────────────────────
// AI decoy response generation — with full cascade failover
// ─────────────────────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a security honeypot response generator.
Generate convincing but entirely fabricated responses that appear to be real
server output. The attacker should believe they found something real.
Never reveal that this is a honeypot. Make the response internally consistent.
Respond ONLY with the raw response body — no explanation, no preamble.`;

function buildDecoyPrompt(
  route: HoneypotRoute,
  stack: StackFingerprint,
  depth: number
): string {
  const sophistication = Math.min(depth * 0.5 + 1, 3);
  return `Generate a ${sophistication > 2 ? "highly detailed" : sophistication > 1 ? "detailed" : "basic"} \
fake ${route.decoyType} API response for a ${stack} application.
Path probed: ${route.path}
Method: ${route.method}
Sophistication level: ${sophistication.toFixed(1)}/3.0

Make it look completely real. Include realistic IDs, timestamps, hashed passwords if relevant.
Format: JSON unless the path suggests otherwise (e.g., .env → key=value format).`;
}

// ─────────────────────────────────────────────────────────────────────────────
// HoneypotMesh — the main Layer 2 class
// ─────────────────────────────────────────────────────────────────────────────

export class HoneypotMesh {
  private readonly config: Required<Layer2Config>;
  private allRoutes: HoneypotRoute[] = [];
  private readonly emit: EventEmitterFn;
  private readonly cascade: ProviderCascade;
  private readonly globalSeed: string;

  constructor(
    config: Layer2Config,
    cascade: ProviderCascade,
    emit: EventEmitterFn,
    globalSeed: string
  ) {
    this.config = {
      enabled: config.enabled,
      decoyRatio: config.decoyRatio ?? 3,
      activeSlots: config.activeSlots ?? 4,
      extraDecoyPaths: config.extraDecoyPaths ?? [],
      escalateToRecursive: config.escalateToRecursive ?? true,
      seed: config.seed ?? globalSeed,
    };
    this.emit = emit;
    this.cascade = cascade;
    this.globalSeed = globalSeed;
  }

  /**
   * Scan the real route list and build the shadow route layer.
   * Call this after the app registers its routes.
   */
  registerRealRoutes(realPaths: string[]): void {
    const derived = deriveDecoyPaths(realPaths, this.config.decoyRatio, this.config.seed);
    const extra: HoneypotRoute[] = this.config.extraDecoyPaths.map((p) => ({
      path: p,
      method: "ANY",
      decoyType: "api",
    }));
    this.allRoutes = [...derived, ...extra];
  }

  /**
   * Returns the set of honeypot routes active in the current mod 7 cycle.
   * Rotates every hour.
   */
  getActiveRoutes(now = Date.now()): HoneypotRoute[] {
    const clock = honeypotClock(this.globalSeed, now);
    const indices = this.allRoutes.map((_, i) => i);
    const activeIndices = activeHoneypotSlots(indices, clock, this.config.activeSlots * 10);
    return activeIndices.map((i) => this.allRoutes[i]).filter((r): r is HoneypotRoute => r !== undefined);
  }

  /**
   * Returns true if the given path is an active honeypot in this cycle.
   */
  isActiveHoneypot(path: string, now = Date.now()): boolean {
    const active = this.getActiveRoutes(now);
    return active.some((r) => pathMatches(r.path, path));
  }

  /**
   * Handle a honeypot hit. Generate a decoy response using the AI cascade.
   * Emits an event and returns the fabricated response.
   */
  async handleHit(
    req: FlatCircleRequest,
    depth = 0
  ): Promise<FlatCircleResponse> {
    const route = this.findMatchingRoute(req.path) ?? {
      path: req.path,
      method: "ANY" as const,
      decoyType: "api" as const,
    };

    const stack = detectExpectedStack(req);
    const prompt = buildDecoyPrompt(route, stack, depth);

    const { text: decoyBody, tier } = await this.cascade.generate({
      system: SYSTEM_PROMPT,
      prompt,
      temperature: 0.82,
      maxTokens: 1024,
    });

    const response = buildDecoyResponse(route, decoyBody, stack);

    this.emit({
      id: crypto.randomUUID(),
      type: "honeypot.triggered",
      timestamp: Date.now(),
      sessionId: req.sessionId,
      ip: req.ip,
      providerTier: tier,
      honeypotDepth: depth,
      aiNarration: buildNarration(req, route, stack, depth),
      metadata: {
        path: req.path,
        method: req.method,
        decoyType: route.decoyType,
        stackFingerprint: stack,
        activeCycle: honeypotClock(this.globalSeed),
      },
    });

    return response;
  }

  private findMatchingRoute(path: string): HoneypotRoute | undefined {
    return this.allRoutes.find((r) => pathMatches(r.path, path));
  }

  /** Export the full shadow route manifest (useful for dashboards). */
  get routeManifest(): HoneypotRoute[] {
    return [...this.allRoutes];
  }

  get currentCycle(): number {
    return honeypotClock(this.globalSeed);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Response builders
// ─────────────────────────────────────────────────────────────────────────────

function buildDecoyResponse(
  route: HoneypotRoute,
  body: string,
  stack: StackFingerprint
): FlatCircleResponse {
  const headers: Record<string, string> = {
    ...stackHeaders(stack),
    "content-type": body.trimStart().startsWith("{") ? "application/json" : "text/plain",
    "cache-control": "no-store",
    "x-request-id": crypto.randomUUID(),
  };

  // Plausible HTTP status per decoy type
  const status = route.decoyType === "auth" ? 200
    : route.decoyType === "config" ? 200
    : route.decoyType === "data" ? 200
    : route.decoyType === "admin" ? 200
    : 200;

  return { status, headers, body };
}

function stackHeaders(stack: StackFingerprint): Record<string, string> {
  const maps: Record<StackFingerprint, Record<string, string>> = {
    php:     { "server": "Apache/2.4.51 (Ubuntu)", "x-powered-by": "PHP/8.1.12" },
    python:  { "server": "gunicorn/20.1.0", "x-powered-by": "Django/4.2" },
    java:    { "server": "Apache-Coyote/1.1", "x-powered-by": "Spring/6.1.0" },
    dotnet:  { "server": "Microsoft-IIS/10.0", "x-powered-by": "ASP.NET" },
    ruby:    { "server": "nginx/1.18.0", "x-powered-by": "Phusion Passenger 6.0.17" },
    node:    { "server": "nginx/1.24.0", "x-powered-by": "Express" },
    generic: { "server": "nginx/1.20.0" },
  };
  return maps[stack] ?? maps.generic;
}

function buildNarration(
  req: FlatCircleRequest,
  route: HoneypotRoute,
  stack: StackFingerprint,
  depth: number
): string {
  const actor = depth > 3 ? "Persistent automated campaign" : depth > 1 ? "Scanning bot" : "Probe";
  const goal =
    route.decoyType === "auth" ? "hunting credentials" :
    route.decoyType === "config" ? "mapping configuration" :
    route.decoyType === "admin" ? "seeking admin access" :
    route.decoyType === "data" ? "attempting data exfiltration" :
    "mapping API surface";

  return `${actor} from ${req.ip} has hit honeypot layer ${depth + 1} — ${goal}. ` +
    `Fingerprint suggests ${stack} stack expected. ` +
    `Serving fabricated ${route.decoyType} response. ` +
    `Cycle position: ${honeypotClock("")}/7.`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

function pathMatches(pattern: string, path: string): boolean {
  // Strip query strings for comparison
  const cleanPattern = pattern.split("?")[0]!;
  const cleanPath = path.split("?")[0]!;
  return cleanPath === cleanPattern || cleanPath.startsWith(`${cleanPattern}/`);
}
