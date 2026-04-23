/**
 * Flat Circle — Full TypeScript interface surface.
 *
 * Thirteen layers. Four AI tiers. One philosophy:
 * don't just guard the wall — make the interior hostile.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Shared primitives
// ─────────────────────────────────────────────────────────────────────────────

export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";
export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

export interface FlatCircleRequest {
  readonly method: HttpMethod;
  readonly url: string;
  readonly path: string;
  readonly headers: Record<string, string>;
  readonly query: Record<string, string>;
  readonly body: unknown;
  readonly ip: string;
  readonly sessionId: string;
  readonly timestamp: number;
}

export interface FlatCircleResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

export interface LayerContext {
  readonly request: FlatCircleRequest;
  readonly sessionId: string;
  readonly mod7Clocks: Mod7Clocks;
  readonly providerTier: AIProviderTier;
  readonly isShadowSession: boolean;
  readonly honeypotDepth: number;
  metadata: Record<string, unknown>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Mod 7 rhythm
// ─────────────────────────────────────────────────────────────────────────────

/** The five independent mod 7 clocks running across layers 2, 5, 7, 10, 11. */
export interface Mod7Clocks {
  /** Layer 2: honeypot rotation — mod 7 of current hour */
  readonly honeypot: number;
  /** Layer 5: temporal gating — mod 7 of session-specific prime seed */
  readonly temporal: number;
  /** Layer 7: entropy injection — mod 7 of session hash */
  readonly entropy: number;
  /** Layer 10: route morphing — mod 7 of current day */
  readonly routes: number;
  /** Layer 11: Merkle verification — mod 7 of transaction count */
  readonly merkle: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// AI Provider configuration (4-tier cascade)
// ─────────────────────────────────────────────────────────────────────────────

export type AIProviderTier = "openai" | "anthropic" | "ollama" | "static";

export interface OpenAIProviderConfig {
  readonly apiKey: string;
  readonly model?: string;
  /** Embedding model for behavioral contracts. @default "text-embedding-3-large" */
  readonly embeddingModel?: string;
  readonly baseURL?: string;
  readonly organization?: string;
  readonly maxRetries?: number;
  readonly timeoutMs?: number;
}

export interface AnthropicProviderConfig {
  readonly apiKey: string;
  /** @default "claude-sonnet-4-5" */
  readonly model?: string;
  readonly baseURL?: string;
  readonly maxRetries?: number;
  readonly timeoutMs?: number;
}

export interface OllamaProviderConfig {
  /** Ollama API base URL. @default "http://localhost:11434" */
  readonly baseURL?: string;
  /** Model for generation. @default "llama3" */
  readonly model?: string;
  /** Model for embeddings. @default "nomic-embed-text" */
  readonly embeddingModel?: string;
  readonly timeoutMs?: number;
}

export interface StaticFallbackConfig {
  /**
   * Directory path to pre-generated static decoy response libraries.
   * If omitted, built-in defaults are used.
   */
  readonly decoyLibraryPath?: string;
  /** Max responses to keep in memory. @default 500 */
  readonly cacheSize?: number;
}

export interface AIProviderConfig {
  /** Tier 1: OpenAI GPT-4o (primary). Full capability. */
  readonly openai?: OpenAIProviderConfig;
  /** Tier 2: Anthropic Claude (secondary). Seamless failover. */
  readonly anthropic?: AnthropicProviderConfig;
  /** Tier 3: Local Ollama (tertiary). Zero external dependency. */
  readonly ollama?: OllamaProviderConfig;
  /** Tier 4: Static fallback (always available). Zero latency. */
  readonly static?: StaticFallbackConfig;
  /**
   * How often to attempt recovery to a higher-capability tier (seconds).
   * @default 300
   */
  readonly recoveryIntervalSeconds?: number;
  /**
   * Starting tier on initialization. Defaults to the highest configured tier.
   */
  readonly startingTier?: AIProviderTier;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 1 — Onion Interior
// ─────────────────────────────────────────────────────────────────────────────

export interface Layer1Config {
  readonly enabled: boolean;
  /**
   * Number of isolated pipeline stages. Each stage is stateless and knows
   * only its immediate context. @default 5
   */
  readonly stageCount?: number;
  /**
   * Maximum time (ms) a single stage is permitted to run before it is
   * bypassed and the request continues. @default 50
   */
  readonly stageTimeoutMs?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 2 — Honeypot Mesh
// ─────────────────────────────────────────────────────────────────────────────

export interface HoneypotRoute {
  readonly path: string;
  readonly method: HttpMethod | "ANY";
  readonly decoyType: "api" | "admin" | "auth" | "data" | "config" | "health";
}

export interface Layer2Config {
  readonly enabled: boolean;
  /**
   * Ratio of honeypot routes generated per real route.
   * @default 3
   */
  readonly decoyRatio?: number;
  /**
   * How many honeypot route slots are active per mod 7 cycle position.
   * @default 4
   */
  readonly activeSlots?: number;
  /**
   * Manually specify additional honeypot paths beyond auto-generated ones.
   */
  readonly extraDecoyPaths?: string[];
  /**
   * Whether to escalate to Layer 8 recursive mode after a probe is detected.
   * @default true
   */
  readonly escalateToRecursive?: boolean;
  /** Seed string for deterministic honeypot generation across restarts. */
  readonly seed?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 3 — Merkle-Backed Canary Token Fabric
// ─────────────────────────────────────────────────────────────────────────────

export interface CanaryWebhookConfig {
  readonly url: string;
  readonly secret?: string;
  readonly headers?: Record<string, string>;
}

export interface Layer3Config {
  readonly enabled: boolean;
  /**
   * Token types to embed. @default ["response", "asset", "query"]
   */
  readonly tokenTypes?: Array<"response" | "asset" | "query" | "header">;
  /**
   * Webhook(s) to call when a canary fires.
   */
  readonly webhooks?: CanaryWebhookConfig[];
  /**
   * Slack webhook URL for canary alerts. Convenience shorthand.
   */
  readonly slackWebhook?: string;
  /**
   * Discord webhook URL for canary alerts.
   */
  readonly discordWebhook?: string;
  /**
   * Embedding interval in response payloads, as a mod 7 position multiplier.
   * @default 7
   */
  readonly embeddingInterval?: number;
  /**
   * Whether to embed tokens in static assets (JS, CSS, images via metadata).
   * @default true
   */
  readonly embedInAssets?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 4 — AI Behavioral Contract Engine
// ─────────────────────────────────────────────────────────────────────────────

export interface Layer4Config {
  readonly enabled: boolean;
  /**
   * Number of requests to collect before the baseline is considered trained.
   * During this window no requests are blocked. @default 1000
   */
  readonly learningWindowRequests?: number;
  /**
   * Cosine distance threshold above which a request is flagged as anomalous.
   * Range [0, 2]. Lower = more sensitive. @default 0.35
   */
  readonly anomalyThreshold?: number;
  /**
   * What happens when a request crosses the anomaly threshold.
   * @default "reroute"
   */
  readonly anomalyAction?: "reroute" | "ratelimit" | "block" | "flag";
  /**
   * How often (requests) to update the rolling behavioral baseline.
   * @default 100
   */
  readonly baselineUpdateInterval?: number;
  /**
   * Enable continuous learning — baseline updates perpetually.
   * @default true
   */
  readonly continuousLearning?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 5 — Temporal Decoys
// ─────────────────────────────────────────────────────────────────────────────

export interface Layer5Config {
  readonly enabled: boolean;
  /**
   * Minimum microsecond delay added to responses. @default 100
   */
  readonly minDelayMicros?: number;
  /**
   * Maximum microsecond delay added to responses. @default 5000
   */
  readonly maxDelayMicros?: number;
  /**
   * Operations that require mod 7 timestamp validation.
   * If the timestamp component mod 7 does not equal the session seed value,
   * the request is silently rerouted.
   * @default []
   */
  readonly gatedOperations?: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 6 — Syntactic Mimicry
// ─────────────────────────────────────────────────────────────────────────────

export type FingerprintPersona =
  | "php-apache"
  | "rails-nginx"
  | "django-gunicorn"
  | "asp-net-iis"
  | "wordpress-apache"
  | "spring-tomcat"
  | "laravel-nginx"
  | "random";

export interface Layer6Config {
  readonly enabled: boolean;
  /**
   * The fake technology fingerprint to present.
   * "random" picks a different persona per session. @default "random"
   */
  readonly persona?: FingerprintPersona;
  /**
   * Spoof the Server response header. @default true
   */
  readonly spoofServerHeader?: boolean;
  /**
   * Spoof X-Powered-By header. @default true
   */
  readonly spoofPoweredBy?: boolean;
  /**
   * Spoof error pages to match the persona's expected error format.
   * @default true
   */
  readonly spoofErrorPages?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 7 — Entropy Injection
// ─────────────────────────────────────────────────────────────────────────────

export interface Layer7Config {
  readonly enabled: boolean;
  /**
   * Number of ghost headers injected per response.
   * Actual count = base + (mod7.entropy * 2). @default 3
   */
  readonly ghostHeadersBase?: number;
  /**
   * Number of ghost JSON keys injected into JSON responses.
   * @default 2
   */
  readonly ghostJsonKeysBase?: number;
  /**
   * Prefix used for ghost headers to make them look plausible.
   * @default "X-Cache"
   */
  readonly ghostHeaderPrefix?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 8 — Recursive Honeypots
// ─────────────────────────────────────────────────────────────────────────────

export interface Layer8Config {
  readonly enabled: boolean;
  /**
   * Maximum recursive depth before the loop truly has no bottom.
   * At max depth the system wraps back without revealing that it does so.
   * @default 12
   */
  readonly maxDepth?: number;
  /**
   * How much more sophisticated each recursive layer is vs the previous.
   * Feeds into AI prompt construction. @default 1.3
   */
  readonly sophisticationMultiplier?: number;
  /**
   * If true, the AI narrates what it believes the attacker's goal is
   * and tailors decoy content accordingly. @default true
   */
  readonly goalInference?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 9 — Session Shadowing
// ─────────────────────────────────────────────────────────────────────────────

export type ThreatClass =
  | "script-kiddie"
  | "automated-scanner"
  | "sophisticated-actor"
  | "competitor-scraper"
  | "nation-state"
  | "unknown";

export interface Layer9Config {
  readonly enabled: boolean;
  /**
   * Anomaly score (from Layer 4) above which a session is shadowed.
   * @default 0.6
   */
  readonly shadowThreshold?: number;
  /**
   * Maximum concurrent shadow sessions. @default 500
   */
  readonly maxShadowSessions?: number;
  /**
   * Whether to use AI to classify threat actors in shadow sessions.
   * @default true
   */
  readonly aiClassification?: boolean;
  /**
   * Webhook to receive real-time threat classification events.
   */
  readonly classificationWebhook?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 10 — Morphic Routes
// ─────────────────────────────────────────────────────────────────────────────

export interface Layer10Config {
  readonly enabled: boolean;
  /**
   * How aggressively routes shift. "subtle" adds/removes a few paths per
   * cycle. "aggressive" remaps the majority. @default "moderate"
   */
  readonly morphIntensity?: "subtle" | "moderate" | "aggressive";
  /**
   * Stable canonical paths that are NEVER remapped regardless of intensity.
   * Legitimate users always receive correct routing here.
   */
  readonly canonicalPaths?: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 11 — Merkle Session Integrity
// ─────────────────────────────────────────────────────────────────────────────

export interface Layer11Config {
  readonly enabled: boolean;
  /**
   * Hashing algorithm for Merkle leaves. @default "sha256"
   */
  readonly algorithm?: "sha256" | "sha512" | "blake2b512";
  /**
   * How many leaves to accumulate before recomputing the root.
   * Recomputation also triggers on mod7.merkle transition. @default 32
   */
  readonly batchSize?: number;
  /**
   * Persist the Merkle tree across restarts. Requires an adapter.
   * @default false
   */
  readonly persist?: boolean;
  /**
   * Include honeypot interactions in the audit tree. @default true
   */
  readonly includeHoneypotLeaves?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 12 — Collective Threat Intelligence
// ─────────────────────────────────────────────────────────────────────────────

export interface Layer12Config {
  readonly enabled: boolean;
  /**
   * Flat Circle cloud endpoint for collective intelligence sync.
   * Requires a valid apiKey in root config.
   */
  readonly syncEndpoint?: string;
  /**
   * How often to push anonymized aggregates (seconds). @default 300
   */
  readonly syncIntervalSeconds?: number;
  /**
   * Immediately escalate when a probe matches a known campaign.
   * @default true
   */
  readonly campaignMatchEscalation?: boolean;
  /**
   * Minimum campaign match confidence (0–1) to trigger escalation.
   * @default 0.8
   */
  readonly matchConfidenceThreshold?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 13 — Frame Narrative Proxy Wrapper
// ─────────────────────────────────────────────────────────────────────────────

export type ProxyDeployTarget = "node" | "cloudflare-worker" | "docker" | "railway";

export interface ProxyTLSConfig {
  readonly certPath: string;
  readonly keyPath: string;
  readonly caPath?: string;
}

export interface Layer13Config {
  readonly enabled: boolean;
  /**
   * The origin URL that Flat Circle proxies and protects.
   * Required when Layer 13 is enabled.
   */
  readonly originUrl: string;
  /**
   * Port the Flat Circle proxy listens on. @default 8080
   */
  readonly listenPort?: number;
  /**
   * Deployment target — shapes the server adapter used. @default "node"
   */
  readonly deployTarget?: ProxyDeployTarget;
  /**
   * TLS configuration for HTTPS termination at the proxy.
   * If omitted the proxy operates on HTTP (suitable behind a load balancer).
   */
  readonly tls?: ProxyTLSConfig;
  /**
   * Trusted proxy IPs or CIDR ranges for X-Forwarded-For trust.
   */
  readonly trustedProxies?: string[];
  /**
   * Maximum request body size the proxy will buffer (bytes). @default 10485760
   */
  readonly maxBodyBytes?: number;
  /**
   * Connection timeout to origin (ms). @default 30000
   */
  readonly originTimeoutMs?: number;
  /**
   * Strip these headers from origin responses before forwarding to clients.
   * Prevents real technology fingerprints from leaking.
   */
  readonly stripOriginHeaders?: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage adapters
// ─────────────────────────────────────────────────────────────────────────────

export interface RedisAdapterConfig {
  readonly url: string;
  readonly keyPrefix?: string;
  readonly ttlSeconds?: number;
}

export interface PostgresAdapterConfig {
  readonly connectionString: string;
  readonly schema?: string;
  readonly poolSize?: number;
}

export interface MongoAdapterConfig {
  readonly uri: string;
  readonly database?: string;
  readonly collection?: string;
}

export interface StorageAdapterConfig {
  readonly redis?: RedisAdapterConfig;
  readonly postgres?: PostgresAdapterConfig;
  readonly mongo?: MongoAdapterConfig;
}

// ─────────────────────────────────────────────────────────────────────────────
// Alerting webhooks
// ─────────────────────────────────────────────────────────────────────────────

export interface AlertingConfig {
  readonly slack?: string;
  readonly discord?: string;
  readonly email?: {
    readonly to: string | string[];
    readonly from: string;
    readonly smtpUrl: string;
  };
  readonly webhook?: {
    readonly url: string;
    readonly secret?: string;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface DashboardConfig {
  readonly enabled: boolean;
  /** Port to serve the dashboard on. @default 3001 */
  readonly port?: number;
  /** Bearer token required to access the dashboard. */
  readonly accessToken?: string;
  /**
   * Allowed origin(s) for dashboard WebSocket connections.
   */
  readonly allowedOrigins?: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Root FlatCircleConfig — the single configuration object
// ─────────────────────────────────────────────────────────────────────────────

export interface LayerConfig {
  readonly layer1?: Layer1Config;
  readonly layer2?: Layer2Config;
  readonly layer3?: Layer3Config;
  readonly layer4?: Layer4Config;
  readonly layer5?: Layer5Config;
  readonly layer6?: Layer6Config;
  readonly layer7?: Layer7Config;
  readonly layer8?: Layer8Config;
  readonly layer9?: Layer9Config;
  readonly layer10?: Layer10Config;
  readonly layer11?: Layer11Config;
  readonly layer12?: Layer12Config;
  readonly layer13?: Layer13Config;
}

export interface FlatCircleConfig {
  /**
   * Optional API key for Flat Circle cloud features (Layer 12, dashboard sync).
   */
  readonly apiKey?: string;

  /**
   * Environment label. Used in log context and dashboard. @default "production"
   */
  readonly environment?: string;

  /**
   * Log level. @default "warn"
   */
  readonly logLevel?: LogLevel;

  /** AI provider cascade configuration. */
  readonly ai: AIProviderConfig;

  /** Per-layer configuration. Each layer is individually toggleable. */
  readonly layers: LayerConfig;

  /**
   * Optional storage adapters for persistence.
   * Required for Layer 11 persistence and Layer 12 history.
   */
  readonly storage?: StorageAdapterConfig;

  /** Alerting webhook configuration. */
  readonly alerting?: AlertingConfig;

  /** Dashboard configuration. */
  readonly dashboard?: DashboardConfig;

  /**
   * Global mod 7 seed — blended with layer-specific seeds for the
   * rhythm system. Use a random string unique to your deployment.
   */
  readonly mod7GlobalSeed?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime event types (emitted to dashboard and webhooks)
// ─────────────────────────────────────────────────────────────────────────────

export type EventType =
  | "honeypot.triggered"
  | "honeypot.recursive.descent"
  | "canary.fired"
  | "behavioral.anomaly"
  | "session.shadowed"
  | "threat.classified"
  | "merkle.root.updated"
  | "merkle.tamper.detected"
  | "provider.failover"
  | "provider.recovered"
  | "campaign.matched"
  | "route.morphed"
  | "temporal.gate.rejected";

export interface FlatCircleEvent {
  readonly id: string;
  readonly type: EventType;
  readonly timestamp: number;
  readonly sessionId: string;
  readonly ip: string;
  readonly providerTier: AIProviderTier;
  readonly threatClass?: ThreatClass;
  readonly honeypotDepth?: number;
  readonly aiNarration?: string;
  readonly metadata: Record<string, unknown>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Middleware handler signature — framework-agnostic
// ─────────────────────────────────────────────────────────────────────────────

export type NextFn = () => Promise<void> | void;

export type MiddlewareHandler = (
  ctx: LayerContext,
  response: FlatCircleResponse,
  next: NextFn
) => Promise<void> | void;

export type EventEmitterFn = (event: FlatCircleEvent) => void;
