/**
 * Layer 13 — The Frame Narrative Proxy Wrapper
 *
 * The outermost layer. Flat Circle deploys as a standalone reverse proxy
 * that sits completely outside any existing application.
 * No code changes. No installation. No developer access required.
 *
 * Point DNS at Flat Circle. Done. The app is coated.
 *
 * Like a frame narrative in literature, the attacker only ever reads the
 * frame — the real story is somewhere they never reach.
 *
 * Deployable as:
 *   - Node.js server (@hono/node-server)
 *   - Cloudflare Worker (native Hono)
 *   - Docker container (Dockerfile included)
 *   - Railway service (via Dockerfile)
 *
 * Configuration: single flat-circle.yaml file. Nothing else required.
 */

import { Hono } from "hono";
import type { Context as HonoCtx, Next } from "hono";
import type {
  FlatCircleConfig,
  FlatCircleRequest,
  FlatCircleResponse,
  FlatCircleEvent,
  EventEmitterFn,
  HttpMethod,
  Layer13Config,
} from "@flat-circle/core/types";
import { ProviderCascade } from "@flat-circle/core/provider-cascade";
import { HoneypotMesh } from "@flat-circle/core/layers/layer2-honeypot";
import { RecursiveHoneypot } from "@flat-circle/core/layers/layer8-recursive";
import { MerkleIntegrityEngine } from "@flat-circle/core/layers/layer11-merkle";
import { computeMod7Clocks } from "@flat-circle/core/mod7";
import { Pipeline, createContext, createResponse } from "@flat-circle/core/pipeline";
import { buildMimicryHeaders } from "./layers/layer6-mimicry.js";
import { injectEntropy } from "./layers/layer7-entropy.js";
import { applySyntacticMimicry } from "./layers/layer6-mimicry.js";
import { EventBus } from "./event-bus.js";

// ─────────────────────────────────────────────────────────────────────────────
// Session ID extraction / generation
// ─────────────────────────────────────────────────────────────────────────────

function extractSessionId(c: HonoCtx): string {
  const cookie = c.req.header("cookie") ?? "";
  const match = /fc_sid=([^;]+)/.exec(cookie);
  return match?.[1] ?? crypto.randomUUID();
}

function extractIp(c: HonoCtx, trustedProxies: string[]): string {
  const forwarded = c.req.header("x-forwarded-for");
  if (forwarded) {
    const ips = forwarded.split(",").map((s) => s.trim());
    // Return the first non-trusted IP
    for (const ip of ips) {
      if (!trustedProxies.includes(ip)) return ip;
    }
    return ips[0] ?? "unknown";
  }
  return c.req.header("cf-connecting-ip") ??
         c.req.header("x-real-ip") ??
         "unknown";
}

function honoRequestToFc(c: HonoCtx, sessionId: string, ip: string): FlatCircleRequest {
  const url = new URL(c.req.url);
  const headers: Record<string, string> = {};
  c.req.raw.headers.forEach((v, k) => { headers[k] = v; });
  const query: Record<string, string> = {};
  url.searchParams.forEach((v, k) => { query[k] = v; });

  return {
    method: c.req.method as HttpMethod,
    url: c.req.url,
    path: url.pathname,
    headers,
    query,
    body: null, // Body is forwarded raw — not parsed in proxy mode
    ip,
    sessionId,
    timestamp: Date.now(),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Session cookie injection
// ─────────────────────────────────────────────────────────────────────────────

function sessionCookieHeader(sessionId: string): string {
  return `fc_sid=${sessionId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Origin proxy — forward legitimate requests to the real app
// ─────────────────────────────────────────────────────────────────────────────

async function proxyToOrigin(
  c: HonoCtx,
  originUrl: string,
  stripHeaders: string[],
  timeoutMs: number
): Promise<Response> {
  const target = new URL(c.req.url);
  target.protocol = new URL(originUrl).protocol;
  target.host = new URL(originUrl).host;

  const reqHeaders = new Headers(c.req.raw.headers);
  // Remove stripped headers to hide real tech stack from origin leakage
  for (const h of stripHeaders) reqHeaders.delete(h);
  reqHeaders.set("x-forwarded-for", c.req.header("x-real-ip") ?? "unknown");
  reqHeaders.set("x-flat-circle-proxy", "1");

  const body =
    c.req.method !== "GET" && c.req.method !== "HEAD"
      ? await c.req.raw.arrayBuffer()
      : undefined;

  const res = await fetch(target.toString(), {
    method: c.req.method,
    headers: reqHeaders,
    body: body ?? null,
    signal: AbortSignal.timeout(timeoutMs),
    // @ts-expect-error — duplex needed for streaming in some runtimes
    duplex: "half",
  });

  return res;
}

// ─────────────────────────────────────────────────────────────────────────────
// FlatCircleProxy — the main Layer 13 class
// ─────────────────────────────────────────────────────────────────────────────

export class FlatCircleProxy {
  readonly app: Hono;
  private readonly config: FlatCircleConfig;
  private readonly layer13: Required<Layer13Config>;
  private readonly cascade: ProviderCascade;
  private readonly eventBus: EventBus;
  private readonly honeypotMesh: HoneypotMesh;
  private readonly recursiveHoneypot: RecursiveHoneypot;
  private readonly merkleEngine: MerkleIntegrityEngine;
  private readonly globalSeed: string;

  constructor(config: FlatCircleConfig) {
    if (!config.layers.layer13?.enabled) {
      throw new Error("FlatCircleProxy requires layer13 to be enabled.");
    }

    this.config = config;
    this.globalSeed = config.mod7GlobalSeed ?? "flat-circle-default-seed";
    this.layer13 = {
      enabled: true,
      originUrl: config.layers.layer13.originUrl,
      listenPort: config.layers.layer13.listenPort ?? 8080,
      deployTarget: config.layers.layer13.deployTarget ?? "node",
      tls: config.layers.layer13.tls,
      trustedProxies: config.layers.layer13.trustedProxies ?? [],
      maxBodyBytes: config.layers.layer13.maxBodyBytes ?? 10_485_760,
      originTimeoutMs: config.layers.layer13.originTimeoutMs ?? 30_000,
      stripOriginHeaders: config.layers.layer13.stripOriginHeaders ?? [
        "x-powered-by", "server", "x-aspnet-version",
        "x-aspnetmvc-version", "x-generator",
      ],
    };

    this.eventBus = new EventBus(config.alerting);
    const emit: EventEmitterFn = (e) => this.eventBus.emit(e);

    this.cascade = new ProviderCascade(config.ai, emit);

    this.honeypotMesh = new HoneypotMesh(
      config.layers.layer2 ?? { enabled: true },
      this.cascade,
      emit,
      this.globalSeed
    );

    this.recursiveHoneypot = new RecursiveHoneypot(
      config.layers.layer8 ?? { enabled: true },
      this.cascade,
      emit
    );

    this.merkleEngine = new MerkleIntegrityEngine(
      config.layers.layer11 ?? { enabled: true },
      emit,
      this.globalSeed
    );

    this.app = new Hono();
    this.mountMiddleware();
  }

  private mountMiddleware(): void {
    const { layer13 } = this;

    this.app.use("*", async (c: HonoCtx, next: Next) => {
      const sessionId = extractSessionId(c);
      const ip = extractIp(c, layer13.trustedProxies);
      const req = honoRequestToFc(c, sessionId, ip);

      // ── Mod 7 clock snapshot for this request ──
      const clocks = computeMod7Clocks({
        sessionId,
        globalSeed: this.globalSeed,
        transactionCount: this.merkleEngine.getStats().globalTransactionCount,
      });

      // ── Layer 11: record request leaf ──
      if (this.config.layers.layer11?.enabled !== false) {
        this.merkleEngine.recordRequest(req);
      }

      // ── Layer 6: replace server fingerprint headers ──
      const mimicryHeaders = this.config.layers.layer6?.enabled !== false
        ? buildMimicryHeaders(this.config.layers.layer6 ?? { enabled: true }, sessionId)
        : {};

      // ── Layer 2/8: honeypot detection ──
      if (
        this.config.layers.layer2?.enabled !== false &&
        this.honeypotMesh.isActiveHoneypot(req.path)
      ) {
        const depth = 0;
        const fcRes = await this.honeypotMesh.handleHit(req, depth);

        // Check if this session should escalate to Layer 8
        if (this.config.layers.layer8?.enabled !== false) {
          const deepRes = await this.recursiveHoneypot.descend(req);
          return buildHonoResponse(c, deepRes, mimicryHeaders, sessionId);
        }
        return buildHonoResponse(c, fcRes, mimicryHeaders, sessionId);
      }

      // ── Check recursive honeypot session continuation ──
      if (this.config.layers.layer8?.enabled !== false) {
        const sessionState = this.recursiveHoneypot.getSessionState(sessionId);
        if (sessionState && sessionState.depth > 0) {
          // This session is already in the recursive loop
          const deepRes = await this.recursiveHoneypot.descend(req);
          return buildHonoResponse(c, deepRes, mimicryHeaders, sessionId);
        }
      }

      // ── Legitimate request — forward to origin ──
      await next();

      let originResponse: Response;
      try {
        originResponse = await proxyToOrigin(
          c,
          layer13.originUrl,
          layer13.stripOriginHeaders,
          layer13.originTimeoutMs
        );
      } catch (err) {
        // Origin is unreachable — return a spoofed 502 that matches the persona
        const fcRes = createResponse(502, { error: "Bad Gateway", code: 502 });
        return buildHonoResponse(c, fcRes, mimicryHeaders, sessionId);
      }

      // Read the origin response body
      const originBody = await originResponse.text();

      // ── Layer 7: entropy injection into response ──
      const entropyBody = this.config.layers.layer7?.enabled !== false
        ? injectEntropy(originBody, clocks.entropy, sessionId, this.config.layers.layer7 ?? { enabled: true })
        : originBody;

      // ── Layer 11: record response leaf ──
      const fcResponseForRecord: FlatCircleResponse = {
        status: originResponse.status,
        headers: Object.fromEntries(originResponse.headers),
        body: entropyBody,
      };
      if (this.config.layers.layer11?.enabled !== false) {
        this.merkleEngine.recordResponse(sessionId, fcResponseForRecord);
      }

      // Build final response with all overlaid headers
      const finalHeaders = new Headers(originResponse.headers);

      // Strip real server fingerprint headers
      for (const h of layer13.stripOriginHeaders) finalHeaders.delete(h);

      // Apply mimicry headers (Layer 6)
      for (const [k, v] of Object.entries(mimicryHeaders)) finalHeaders.set(k, v);

      // Session cookie if not already set
      if (!c.req.header("cookie")?.includes("fc_sid=")) {
        finalHeaders.append("set-cookie", sessionCookieHeader(sessionId));
      }

      // Frame Narrative outer ring marker (visible in proxy headers only)
      finalHeaders.set("x-content-type-options", "nosniff");
      finalHeaders.set("x-frame-options", "SAMEORIGIN");

      return new Response(entropyBody, {
        status: originResponse.status,
        headers: finalHeaders,
      });
    });
  }

  /** Start the proxy server (Node.js mode). Returns the server instance. */
  async listen(): Promise<unknown> {
    if (typeof process !== "undefined" && process.versions?.node) {
      const { serve } = await import("@hono/node-server");
      return serve({
        fetch: this.app.fetch,
        port: this.layer13.listenPort,
      });
    }
    // In Cloudflare Workers, export .fetch directly
    return this.app.fetch;
  }

  /** Cloudflare Worker / edge handler — use this as your worker export. */
  get fetch(): (req: Request) => Promise<Response> {
    return this.app.fetch.bind(this.app);
  }

  /** Subscribe to real-time events (for dashboard integration). */
  onEvent(handler: EventEmitterFn): () => void {
    return this.eventBus.subscribe(handler);
  }

  /** Graceful shutdown. */
  async destroy(): Promise<void> {
    this.cascade.destroy();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Response builder
// ─────────────────────────────────────────────────────────────────────────────

function buildHonoResponse(
  c: HonoCtx,
  fcRes: FlatCircleResponse,
  mimicryHeaders: Record<string, string>,
  sessionId: string
): Response {
  const headers = new Headers();

  for (const [k, v] of Object.entries(fcRes.headers)) {
    headers.set(k, v);
  }
  for (const [k, v] of Object.entries(mimicryHeaders)) {
    headers.set(k, v);
  }
  if (!c.req.header("cookie")?.includes("fc_sid=")) {
    headers.append("set-cookie", sessionCookieHeader(sessionId));
  }

  const body =
    typeof fcRes.body === "string"
      ? fcRes.body
      : JSON.stringify(fcRes.body);

  return new Response(body, { status: fcRes.status, headers });
}

// ─────────────────────────────────────────────────────────────────────────────
// YAML config loader — flat-circle.yaml → FlatCircleConfig
// ─────────────────────────────────────────────────────────────────────────────

export async function loadConfig(yamlPath: string): Promise<FlatCircleConfig> {
  const { readFile } = await import("node:fs/promises");
  const { load } = await import("js-yaml");
  const raw = await readFile(yamlPath, "utf-8");
  const parsed = load(raw) as FlatCircleConfig;
  return parsed;
}

// ─────────────────────────────────────────────────────────────────────────────
// YAML config schema reference
// ─────────────────────────────────────────────────────────────────────────────

export const YAML_CONFIG_SCHEMA = `
# flat-circle.yaml — Full configuration reference
# Every field is optional. Sane defaults apply to everything.

apiKey: "your-flat-circle-api-key"      # For Layer 12 collective intelligence
environment: production
logLevel: warn

ai:
  openai:
    apiKey: \${OPENAI_API_KEY}           # Tier 1 — Primary
    model: gpt-4o
    embeddingModel: text-embedding-3-large
  anthropic:
    apiKey: \${ANTHROPIC_API_KEY}        # Tier 2 — Secondary
    model: claude-sonnet-4-5
  ollama:                               # Tier 3 — Local/air-gap
    baseURL: http://localhost:11434
    model: llama3
    embeddingModel: nomic-embed-text
  recoveryIntervalSeconds: 300

layers:
  layer1: { enabled: true }
  layer2:
    enabled: true
    decoyRatio: 3
    activeSlots: 4
    escalateToRecursive: true
  layer3:
    enabled: true
    slackWebhook: \${SLACK_WEBHOOK_URL}
  layer4:
    enabled: true
    learningWindowRequests: 1000
    anomalyThreshold: 0.35
    anomalyAction: reroute
  layer5:
    enabled: true
    minDelayMicros: 100
    maxDelayMicros: 5000
  layer6:
    enabled: true
    persona: random
  layer7:
    enabled: true
    ghostHeadersBase: 3
  layer8:
    enabled: true
    maxDepth: 12
    sophisticationMultiplier: 1.3
    goalInference: true
  layer9:
    enabled: true
    shadowThreshold: 0.6
    aiClassification: true
  layer10:
    enabled: true
    morphIntensity: moderate
  layer11:
    enabled: true
    algorithm: sha256
    batchSize: 32
  layer12:
    enabled: true
    campaignMatchEscalation: true
  layer13:
    enabled: true
    originUrl: https://your-actual-app.com  # Required
    listenPort: 8080
    deployTarget: node
    originTimeoutMs: 30000

dashboard:
  enabled: true
  port: 3001
  accessToken: \${DASHBOARD_TOKEN}
`;
