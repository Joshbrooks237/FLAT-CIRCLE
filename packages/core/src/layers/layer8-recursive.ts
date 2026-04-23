/**
 * Layer 8 — Recursive Honeypots with AI Depth
 *
 * Honeypot endpoints lead to deeper honeypots, each layer more convincing
 * than the last. At each recursive layer the AI provider stack generates
 * responses that adapt to the attacker's apparent goal.
 *
 * If they appear to be hunting credentials they find increasingly plausible
 * but entirely fabricated credential structures.
 * If they appear to be mapping an API they receive an elaborately false but
 * internally consistent API schema.
 *
 * There is no bottom. No prize. No exit.
 * Just more loop, each iteration more persuasive than the last.
 */

import type {
  Layer8Config,
  FlatCircleRequest,
  FlatCircleResponse,
  FlatCircleEvent,
  EventEmitterFn,
  ThreatClass,
} from "../types.js";
import type { ProviderCascade } from "../provider-cascade.js";

// ─────────────────────────────────────────────────────────────────────────────
// Attacker goal inference
// ─────────────────────────────────────────────────────────────────────────────

type AttackerGoal =
  | "credential-harvest"
  | "api-mapping"
  | "data-exfiltration"
  | "admin-access"
  | "vulnerability-scan"
  | "code-execution"
  | "config-extraction"
  | "unknown";

interface GoalProfile {
  goal: AttackerGoal;
  confidence: number;
  signals: string[];
}

function inferAttackerGoal(req: FlatCircleRequest, sessionHistory: string[]): GoalProfile {
  const path = req.path.toLowerCase();
  const allPaths = [...sessionHistory, req.path].map((p) => p.toLowerCase());
  const signals: string[] = [];
  const scores: Partial<Record<AttackerGoal, number>> = {};

  const add = (goal: AttackerGoal, points: number, signal: string) => {
    scores[goal] = (scores[goal] ?? 0) + points;
    signals.push(signal);
  };

  // Credential hunting
  if (allPaths.some((p) => /password|passwd|credential|secret|token|api.?key|auth/.test(p))) {
    add("credential-harvest", 3, "paths targeting credentials");
  }
  if (allPaths.some((p) => /\.env|config\.json|secrets\.|vault/.test(p))) {
    add("credential-harvest", 2, "config file probing");
    add("config-extraction", 2, "config file probing");
  }

  // API mapping
  if (allPaths.filter((p) => p.startsWith("/api")).length > 3) {
    add("api-mapping", 3, "systematic API path enumeration");
  }
  if (allPaths.some((p) => /swagger|openapi|graphql|schema|\.json/.test(p))) {
    add("api-mapping", 2, "schema discovery attempt");
  }

  // Data exfiltration
  if (allPaths.some((p) => /export|dump|backup|download|data|bulk/.test(p))) {
    add("data-exfiltration", 3, "data export probing");
  }

  // Admin access
  if (allPaths.some((p) => /admin|panel|dashboard|control|manage/.test(p))) {
    add("admin-access", 2, "admin panel targeting");
  }

  // Vulnerability scanning
  const scanPatterns = [".php", ".asp", "cgi-bin", "xmlrpc", "wp-login", "jndi:", "../../"];
  if (allPaths.some((p) => scanPatterns.some((sp) => p.includes(sp)))) {
    add("vulnerability-scan", 3, "known vulnerability patterns detected");
  }

  // Code execution
  if (allPaths.some((p) => /eval|exec|cmd|shell|bash|wget|curl/.test(p))) {
    add("code-execution", 3, "command injection probing");
  }

  // Find highest scoring goal
  const sorted = Object.entries(scores).sort(([, a], [, b]) => b - a);
  const [topGoal, topScore] = sorted[0] ?? ["unknown", 0];

  return {
    goal: (topGoal as AttackerGoal) ?? "unknown",
    confidence: Math.min((topScore as number) / 6, 1),
    signals,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Depth-scaled content generators — system prompts per goal
// ─────────────────────────────────────────────────────────────────────────────

const GOAL_SYSTEMS: Record<AttackerGoal, string> = {
  "credential-harvest": `You are generating a fake credential store for a honeypot system.
The attacker believes they found real credentials. Generate increasingly detailed and convincing
fake credential data. Include realistic usernames, bcrypt/argon2 hashes, API keys in real formats,
session tokens, and database connection strings — all completely fabricated.
CRITICAL: All values are fake. Real credentials must never appear.`,

  "api-mapping": `You are generating a false but internally consistent API schema for a honeypot.
The attacker is mapping an API surface. Generate fake but convincing OpenAPI specs, endpoint lists,
GraphQL schemas, or API documentation — each layer more detailed than the last.
Include realistic-looking endpoints, authentication schemes, and data models. All fake.`,

  "data-exfiltration": `You are generating fake database export data for a honeypot.
The attacker is attempting data exfiltration. Generate convincing fake user records,
transaction data, PII-shaped but entirely fictional data. Include realistic field names,
UUIDs, timestamps, and data shapes. Progressively more detailed per layer. All fabricated.`,

  "admin-access": `You are generating a fake admin interface response for a honeypot.
The attacker seeks admin access. Generate convincing fake admin panel HTML, API responses
showing admin features, user management interfaces, system control panels. All fake.`,

  "vulnerability-scan": `You are generating false vulnerability indicators for a honeypot.
The attacker is scanning for vulnerabilities. Generate responses that suggest real
vulnerabilities exist but lead nowhere — false SQL errors, fake debug output,
plausible-looking but non-functional injection points. All fabricated.`,

  "code-execution": `You are generating false code execution responses for a honeypot.
The attacker is probing for RCE. Generate convincing but fake command output,
shell responses, or server-side execution indicators. Include realistic-looking
but completely harmless and fabricated system information. All fake.`,

  "config-extraction": `You are generating false configuration data for a honeypot.
The attacker wants configuration files. Generate convincing fake .env files,
config JSONs, YAML configurations — with fake credentials, API keys, and settings.
All values are fabricated. Make them convincing.`,

  "unknown": `You are generating a generic honeypot response.
Generate a convincing but entirely fabricated server response appropriate to the
path and context. Be realistic but provide no real information.`,
};

function buildRecursivePrompt(
  req: FlatCircleRequest,
  depth: number,
  goal: AttackerGoal,
  confidence: number,
  sophisticationMultiplier: number
): string {
  const sophistication = Math.min(depth * sophisticationMultiplier, 5).toFixed(1);
  const previousContext = depth > 1
    ? `The attacker has already reached depth ${depth} — they are ${confidence > 0.7 ? "highly" : "moderately"} motivated and persistent. Each layer should be ${sophisticationMultiplier}x more convincing than the last.`
    : "First recursive encounter.";

  return `Depth: ${depth}/${sophistication} sophistication
Path: ${req.path}
Method: ${req.method}
Goal inference: ${goal} (confidence: ${Math.round(confidence * 100)}%)
${previousContext}

Generate a depth-${depth} honeypot response. At this depth the attacker has proven persistence.
The response should be more detailed and convincing than any previous layer.
${depth > 3 ? "Include deeply nested data structures, internal references, and realistic system artifacts." : ""}
${depth > 6 ? "This is deep recursive territory. Make the response a complete, fully elaborated world." : ""}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Next-hop route generation — the hole has no bottom
// ─────────────────────────────────────────────────────────────────────────────

const RABBIT_HOLE_PATHS: Record<AttackerGoal, string[]> = {
  "credential-harvest": [
    "/api/auth/users", "/api/auth/admin", "/vault/secrets", "/admin/credentials",
    "/internal/api-keys", "/system/tokens", "/db/users", "/export/credentials",
  ],
  "api-mapping": [
    "/api/v2/internal", "/api/admin/schema", "/internal/api/docs", "/api/management",
    "/graphql/internal", "/api/system/endpoints", "/v3/admin/api", "/internal/swagger",
  ],
  "data-exfiltration": [
    "/api/data/export", "/admin/database/dump", "/internal/users/all", "/export/bulk",
    "/api/records/full", "/data/backup", "/system/export", "/internal/data/raw",
  ],
  "admin-access": [
    "/admin/panel", "/admin/users", "/admin/system", "/management/dashboard",
    "/control/access", "/superadmin", "/admin/config", "/system/admin",
  ],
  "vulnerability-scan": [
    "/.git/HEAD", "/debug/vars", "/.env.production", "/server-status",
    "/api/debug", "/internal/metrics", "/trace", "/api/error-log",
  ],
  "code-execution": [
    "/api/exec", "/system/cmd", "/internal/eval", "/admin/shell",
    "/debug/eval", "/api/run", "/execute", "/system/run",
  ],
  "config-extraction": [
    "/config/production.json", "/.env.local", "/settings/system", "/admin/config",
    "/internal/config", "/system/settings", "/config/secrets", "/env/production",
  ],
  "unknown": [
    "/api/internal", "/admin", "/system", "/internal",
    "/management", "/control", "/api/v2", "/api/admin",
  ],
};

function nextHopUrl(goal: AttackerGoal, depth: number, sessionId: string): string {
  const paths = RABBIT_HOLE_PATHS[goal];
  // Rotate through paths based on depth and session hash to avoid obvious loops
  const idx = (depth + djb2Hash(sessionId)) % paths.length;
  return paths[idx]!;
}

function djb2Hash(s: string): number {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  }
  return h;
}

// ─────────────────────────────────────────────────────────────────────────────
// RecursiveHoneypot — Layer 8 engine
// ─────────────────────────────────────────────────────────────────────────────

interface SessionState {
  depth: number;
  pathHistory: string[];
  goalProfile: GoalProfile | null;
  firstHitAt: number;
}

export class RecursiveHoneypot {
  private readonly config: Required<Layer8Config>;
  private readonly cascade: ProviderCascade;
  private readonly emit: EventEmitterFn;
  private readonly sessions = new Map<string, SessionState>();

  constructor(config: Layer8Config, cascade: ProviderCascade, emit: EventEmitterFn) {
    this.config = {
      enabled: config.enabled,
      maxDepth: config.maxDepth ?? 12,
      sophisticationMultiplier: config.sophisticationMultiplier ?? 1.3,
      goalInference: config.goalInference ?? true,
    };
    this.cascade = cascade;
    this.emit = emit;
  }

  /**
   * Handle a request at the recursive honeypot layer.
   * The session descends one level deeper each call.
   * The loop never terminates from the attacker's perspective.
   */
  async descend(req: FlatCircleRequest): Promise<FlatCircleResponse> {
    const state = this.getOrCreateSession(req.sessionId, req.path);
    state.depth = Math.min(state.depth + 1, this.config.maxDepth);
    state.pathHistory.push(req.path);

    // Infer what the attacker is after
    const goalProfile = this.config.goalInference
      ? inferAttackerGoal(req, state.pathHistory)
      : { goal: "unknown" as AttackerGoal, confidence: 0, signals: [] };

    state.goalProfile = goalProfile;

    const systemPrompt = GOAL_SYSTEMS[goalProfile.goal];
    const userPrompt = buildRecursivePrompt(
      req,
      state.depth,
      goalProfile.goal,
      goalProfile.confidence,
      this.config.sophisticationMultiplier
    );

    const { text: body, tier } = await this.cascade.generate({
      system: systemPrompt,
      prompt: userPrompt,
      temperature: 0.85 + state.depth * 0.01, // Slightly more creative at depth
      maxTokens: 1024 + state.depth * 256,     // More content at depth
    });

    // Embed a navigation hint into the response pointing to the next layer
    const nextHop = nextHopUrl(goalProfile.goal, state.depth, req.sessionId);
    const responseBody = embedNextHop(body, nextHop, goalProfile.goal, state.depth);

    this.emit({
      id: crypto.randomUUID(),
      type: "honeypot.recursive.descent",
      timestamp: Date.now(),
      sessionId: req.sessionId,
      ip: req.ip,
      providerTier: tier,
      honeypotDepth: state.depth,
      aiNarration: buildRecursiveNarration(req, state, goalProfile),
      metadata: {
        goal: goalProfile.goal,
        confidence: goalProfile.confidence,
        signals: goalProfile.signals,
        nextHop,
        pathHistory: state.pathHistory,
        sophistication: Math.min(state.depth * this.config.sophisticationMultiplier, 5),
      },
    });

    return {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-request-id": crypto.randomUUID(),
        "x-trace-id": `fc-${req.sessionId.slice(0, 8)}`,
        "cache-control": "no-store, no-cache",
      },
      body: responseBody,
    };
  }

  /** Peek at a session's current state (for dashboard and Layer 9 integration). */
  getSessionState(sessionId: string): SessionState | undefined {
    return this.sessions.get(sessionId);
  }

  /** Classify the attacker based on accumulated recursive descent behavior. */
  classifyThreat(sessionId: string): ThreatClass {
    const state = this.sessions.get(sessionId);
    if (!state) return "unknown";

    if (state.depth > 8) return "sophisticated-actor";
    if (state.depth > 4) return "automated-scanner";
    if (state.goalProfile?.goal === "data-exfiltration" && state.depth > 2) return "competitor-scraper";
    if (state.goalProfile?.confidence ?? 0 > 0.8) return "automated-scanner";
    return "script-kiddie";
  }

  private getOrCreateSession(sessionId: string, initialPath: string): SessionState {
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, {
        depth: 0,
        pathHistory: [initialPath],
        goalProfile: null,
        firstHitAt: Date.now(),
      });
    }
    return this.sessions.get(sessionId)!;
  }

  /** Prune sessions older than 4 hours to prevent memory growth. */
  pruneOldSessions(): void {
    const cutoff = Date.now() - 4 * 60 * 60 * 1_000;
    for (const [id, state] of this.sessions) {
      if (state.firstHitAt < cutoff) this.sessions.delete(id);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Response enrichment — embeds the next-hop breadcrumb
// ─────────────────────────────────────────────────────────────────────────────

function embedNextHop(
  body: string,
  nextHop: string,
  goal: AttackerGoal,
  depth: number
): string {
  // Try to embed as a JSON field first
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    // Embed as a plausible field name per goal type
    const fieldName =
      goal === "api-mapping" ? "_links" :
      goal === "admin-access" ? "management_url" :
      goal === "credential-harvest" ? "token_refresh_endpoint" :
      "next_page";

    if (depth < 4) {
      // Early layers: embed the link fairly visibly
      parsed[fieldName] = nextHop;
    } else {
      // Deep layers: bury it in nested data
      const inner = parsed["_meta"] as Record<string, unknown> ?? {};
      inner["href"] = nextHop;
      parsed["_meta"] = inner;
    }
    return JSON.stringify(parsed, null, 2);
  } catch {
    // Non-JSON body — append as a comment or header-style field
    return `${body}\n# Related: ${nextHop}`;
  }
}

function buildRecursiveNarration(
  req: FlatCircleRequest,
  state: SessionState,
  goal: GoalProfile
): string {
  const actor =
    state.depth > 8 ? "Nation-state-pattern actor" :
    state.depth > 5 ? "Sophisticated automated campaign" :
    state.depth > 2 ? "Persistent scanning bot" :
    "Automated probe";

  const goalDesc =
    goal.goal === "credential-harvest" ? "actively hunting credentials" :
    goal.goal === "api-mapping" ? "systematically mapping API surface" :
    goal.goal === "data-exfiltration" ? "attempting data exfiltration" :
    goal.goal === "admin-access" ? "seeking administrative access" :
    goal.goal === "vulnerability-scan" ? "running vulnerability scanner" :
    "exploring unknown objective";

  return `${actor} from ${req.ip} has descended to recursive layer ${state.depth}. ` +
    `Classified as ${goalDesc} (${Math.round((goal.confidence ?? 0) * 100)}% confidence). ` +
    `Serving fabricated depth-${state.depth} response. ` +
    `Session has visited ${state.pathHistory.length} paths. ` +
    `They are going deeper. There is no bottom.`;
}
