/**
 * Flat Circle — Four-Tier AI Provider Cascade
 *
 * Tier 1: OpenAI GPT-4o  — full capability, behavioral embeddings, threat narration
 * Tier 2: Anthropic Claude — seamless failover, identical prompt shape
 * Tier 3: Ollama (local)  — zero external API dependency, air-gap capable
 * Tier 4: Static fallback — always available, zero latency, zero dependencies
 *
 * The slime never stops coating.
 */

import type {
  AIProviderConfig,
  AIProviderTier,
  FlatCircleEvent,
  EventEmitterFn,
} from "./types.js";
import { STATIC_DECOY_LIBRARY, STATIC_EMBEDDINGS } from "./static-fallback.js";

// ─────────────────────────────────────────────────────────────────────────────
// Provider interface
// ─────────────────────────────────────────────────────────────────────────────

export interface GenerateOptions {
  system?: string;
  prompt: string;
  temperature?: number;
  maxTokens?: number;
}

export interface EmbedOptions {
  text: string;
}

export interface AIProvider {
  readonly tier: AIProviderTier;
  generate(opts: GenerateOptions): Promise<string>;
  embed(opts: EmbedOptions): Promise<number[]>;
  isAvailable(): Promise<boolean>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier 1: OpenAI
// ─────────────────────────────────────────────────────────────────────────────

class OpenAIProvider implements AIProvider {
  readonly tier: AIProviderTier = "openai";
  private client: unknown = null;

  constructor(private readonly config: NonNullable<AIProviderConfig["openai"]>) {}

  private async getClient(): Promise<{
    chat: { completions: { create: (o: unknown) => Promise<{ choices: Array<{ message: { content: string } }> }> } };
    embeddings: { create: (o: unknown) => Promise<{ data: Array<{ embedding: number[] }> }> };
  }> {
    if (!this.client) {
      try {
        const { OpenAI } = await import("openai");
        this.client = new OpenAI({
          apiKey: this.config.apiKey,
          baseURL: this.config.baseURL,
          organization: this.config.organization,
          maxRetries: this.config.maxRetries ?? 1,
          timeout: this.config.timeoutMs ?? 15_000,
        });
      } catch {
        throw new Error("openai package not installed — add it as a dependency");
      }
    }
    return this.client as ReturnType<typeof this.getClient> extends Promise<infer T> ? T : never;
  }

  async generate(opts: GenerateOptions): Promise<string> {
    const client = await this.getClient();
    const messages: Array<{ role: string; content: string }> = [];
    if (opts.system) messages.push({ role: "system", content: opts.system });
    messages.push({ role: "user", content: opts.prompt });

    const completion = await client.chat.completions.create({
      model: this.config.model ?? "gpt-4o",
      messages,
      temperature: opts.temperature ?? 0.85,
      max_tokens: opts.maxTokens ?? 2048,
    });
    return completion.choices[0]?.message?.content ?? "";
  }

  async embed(opts: EmbedOptions): Promise<number[]> {
    const client = await this.getClient();
    const result = await client.embeddings.create({
      model: this.config.embeddingModel ?? "text-embedding-3-large",
      input: opts.text,
    });
    return result.data[0]?.embedding ?? [];
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.embed({ text: "ping" });
      return true;
    } catch {
      return false;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier 2: Anthropic Claude
// ─────────────────────────────────────────────────────────────────────────────

class AnthropicProvider implements AIProvider {
  readonly tier: AIProviderTier = "anthropic";
  private client: unknown = null;

  constructor(private readonly config: NonNullable<AIProviderConfig["anthropic"]>) {}

  private async getClient(): Promise<{
    messages: { create: (o: unknown) => Promise<{ content: Array<{ type: string; text: string }> }> };
  }> {
    if (!this.client) {
      try {
        const { Anthropic } = await import("@anthropic-ai/sdk");
        this.client = new Anthropic({
          apiKey: this.config.apiKey,
          baseURL: this.config.baseURL,
          maxRetries: this.config.maxRetries ?? 1,
          timeout: this.config.timeoutMs ?? 15_000,
        });
      } catch {
        throw new Error("@anthropic-ai/sdk not installed — add it as a dependency");
      }
    }
    return this.client as ReturnType<typeof this.getClient> extends Promise<infer T> ? T : never;
  }

  async generate(opts: GenerateOptions): Promise<string> {
    const client = await this.getClient();
    const result = await client.messages.create({
      model: this.config.model ?? "claude-sonnet-4-5",
      max_tokens: opts.maxTokens ?? 2048,
      system: opts.system,
      messages: [{ role: "user", content: opts.prompt }],
      temperature: opts.temperature ?? 0.85,
    });
    const block = result.content.find((b) => b.type === "text");
    return block?.text ?? "";
  }

  async embed(_opts: EmbedOptions): Promise<number[]> {
    // Anthropic does not expose embeddings — cascade to next tier for embed tasks
    throw new Error("Anthropic does not provide an embeddings API");
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.generate({ prompt: "ping", maxTokens: 1 });
      return true;
    } catch {
      return false;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier 3: Ollama (local)
// ─────────────────────────────────────────────────────────────────────────────

class OllamaProvider implements AIProvider {
  readonly tier: AIProviderTier = "ollama";
  private readonly baseURL: string;
  private readonly model: string;
  private readonly embeddingModel: string;

  constructor(config: NonNullable<AIProviderConfig["ollama"]>) {
    this.baseURL = config.baseURL ?? "http://localhost:11434";
    this.model = config.model ?? "llama3";
    this.embeddingModel = config.embeddingModel ?? "nomic-embed-text";
  }

  async generate(opts: GenerateOptions): Promise<string> {
    const systemPrefix = opts.system ? `${opts.system}\n\n` : "";
    const body = {
      model: this.model,
      prompt: `${systemPrefix}${opts.prompt}`,
      stream: false,
      options: { temperature: opts.temperature ?? 0.85, num_predict: opts.maxTokens ?? 2048 },
    };
    const res = await fetch(`${this.baseURL}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`Ollama generate failed: ${res.status}`);
    const data = (await res.json()) as { response?: string };
    return data.response ?? "";
  }

  async embed(opts: EmbedOptions): Promise<number[]> {
    const res = await fetch(`${this.baseURL}/api/embeddings`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: this.embeddingModel, prompt: opts.text }),
    });
    if (!res.ok) throw new Error(`Ollama embed failed: ${res.status}`);
    const data = (await res.json()) as { embedding?: number[] };
    return data.embedding ?? [];
  }

  async isAvailable(): Promise<boolean> {
    try {
      const res = await fetch(`${this.baseURL}/api/tags`, { signal: AbortSignal.timeout(3_000) });
      return res.ok;
    } catch {
      return false;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier 4: Static fallback
// ─────────────────────────────────────────────────────────────────────────────

class StaticProvider implements AIProvider {
  readonly tier: AIProviderTier = "static";

  async generate(opts: GenerateOptions): Promise<string> {
    // Route to the appropriate pre-generated library based on prompt keywords
    const lower = opts.prompt.toLowerCase();
    if (lower.includes("credential") || lower.includes("password") || lower.includes("token")) {
      return STATIC_DECOY_LIBRARY.credentials[
        Math.floor(Math.random() * STATIC_DECOY_LIBRARY.credentials.length)
      ] ?? "";
    }
    if (lower.includes("api") || lower.includes("endpoint") || lower.includes("schema")) {
      return STATIC_DECOY_LIBRARY.apiSchemas[
        Math.floor(Math.random() * STATIC_DECOY_LIBRARY.apiSchemas.length)
      ] ?? "";
    }
    if (lower.includes("admin") || lower.includes("dashboard") || lower.includes("panel")) {
      return STATIC_DECOY_LIBRARY.adminPanels[
        Math.floor(Math.random() * STATIC_DECOY_LIBRARY.adminPanels.length)
      ] ?? "";
    }
    return STATIC_DECOY_LIBRARY.generic[
      Math.floor(Math.random() * STATIC_DECOY_LIBRARY.generic.length)
    ] ?? "";
  }

  async embed(opts: EmbedOptions): Promise<number[]> {
    // Deterministic pseudo-embeddings from text hash — no model inference required.
    // Dimensionality: 384 (matches small embedding models).
    return deterministicEmbed(opts.text, 384);
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }
}

/** Deterministic pseudo-embedding from text. Suitable for baseline + delta comparisons. */
function deterministicEmbed(text: string, dims: number): number[] {
  const seed = hashString(text);
  const vec: number[] = new Array(dims);
  let state = seed;
  for (let i = 0; i < dims; i++) {
    state = (state * 1664525 + 1013904223) >>> 0;
    vec[i] = (state / 0xffffffff) * 2 - 1;
  }
  const norm = Math.sqrt(vec.reduce((s, v) => s + v * v, 0));
  return vec.map((v) => v / (norm || 1));
}

function hashString(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h;
}

// ─────────────────────────────────────────────────────────────────────────────
// ProviderCascade — orchestrates failover across all four tiers
// ─────────────────────────────────────────────────────────────────────────────

export interface CascadeState {
  currentTier: AIProviderTier;
  lastFailover: number | null;
  lastFailoverReason: string | null;
  lastRecoveryAttempt: number | null;
}

export class ProviderCascade {
  private readonly providers: AIProvider[];
  private currentIndex: number = 0;
  private readonly recoveryIntervalMs: number;
  private recoveryTimer: ReturnType<typeof setInterval> | null = null;
  private readonly emit: EventEmitterFn;

  public state: CascadeState = {
    currentTier: "static",
    lastFailover: null,
    lastFailoverReason: null,
    lastRecoveryAttempt: null,
  };

  constructor(config: AIProviderConfig, emit: EventEmitterFn) {
    this.emit = emit;
    this.recoveryIntervalMs = (config.recoveryIntervalSeconds ?? 300) * 1_000;

    const providers: AIProvider[] = [];
    if (config.openai) providers.push(new OpenAIProvider(config.openai));
    if (config.anthropic) providers.push(new AnthropicProvider(config.anthropic));
    if (config.ollama) providers.push(new OllamaProvider(config.ollama));
    providers.push(new StaticProvider()); // Always present
    this.providers = providers;

    // Start at the configured or highest-priority tier
    if (config.startingTier) {
      const idx = providers.findIndex((p) => p.tier === config.startingTier);
      this.currentIndex = idx >= 0 ? idx : 0;
    } else {
      this.currentIndex = 0;
    }
    this.state = { ...this.state, currentTier: this.providers[this.currentIndex]?.tier ?? "static" };

    this.startRecoveryLoop();
  }

  /** Generate text via the current provider, cascading on failure. */
  async generate(opts: GenerateOptions): Promise<{ text: string; tier: AIProviderTier }> {
    return this.cascade(
      (p) => p.generate(opts),
      "generate"
    );
  }

  /** Embed text via the current provider, cascading on failure. */
  async embed(opts: EmbedOptions): Promise<{ embedding: number[]; tier: AIProviderTier }> {
    const result = await this.cascade(
      (p) => p.embed(opts),
      "embed"
    );
    return { embedding: result.value, tier: result.tier };
  }

  private async cascade<T>(
    fn: (p: AIProvider) => Promise<T>,
    opName: string
  ): Promise<{ value: T; tier: AIProviderTier }> {
    let attempt = this.currentIndex;
    while (attempt < this.providers.length) {
      const provider = this.providers[attempt];
      if (!provider) break;
      try {
        const value = await fn(provider);
        if (attempt !== this.currentIndex) {
          // Recovered from a further tier back to a better one
          this.setTier(attempt);
        }
        return { value, tier: provider.tier };
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        this.emitFailover(provider.tier, reason);
        attempt++;
      }
    }
    // Should never happen — static is always available
    const staticProvider = this.providers[this.providers.length - 1]!;
    const value = await fn(staticProvider);
    return { value, tier: "static" };
  }

  private setTier(index: number): void {
    const provider = this.providers[index];
    if (!provider) return;
    this.currentIndex = index;
    this.state = { ...this.state, currentTier: provider.tier };
  }

  private emitFailover(fromTier: AIProviderTier, reason: string): void {
    this.state = {
      ...this.state,
      lastFailover: Date.now(),
      lastFailoverReason: reason,
    };
    const next = this.providers[this.currentIndex + 1];
    if (next) {
      this.currentIndex++;
      this.state = { ...this.state, currentTier: next.tier };
    }
    this.emit({
      id: crypto.randomUUID(),
      type: "provider.failover",
      timestamp: Date.now(),
      sessionId: "system",
      ip: "0.0.0.0",
      providerTier: this.state.currentTier,
      metadata: { fromTier, reason, newTier: this.state.currentTier },
    });
  }

  private startRecoveryLoop(): void {
    if (this.recoveryTimer) return;
    this.recoveryTimer = setInterval(async () => {
      if (this.currentIndex === 0) return; // Already at best tier
      this.state = { ...this.state, lastRecoveryAttempt: Date.now() };
      for (let i = 0; i < this.currentIndex; i++) {
        const provider = this.providers[i];
        if (!provider) continue;
        if (await provider.isAvailable()) {
          const previousTier = this.state.currentTier;
          this.setTier(i);
          this.emit({
            id: crypto.randomUUID(),
            type: "provider.recovered",
            timestamp: Date.now(),
            sessionId: "system",
            ip: "0.0.0.0",
            providerTier: this.state.currentTier,
            metadata: { recoveredTo: provider.tier, previousTier },
          });
          break;
        }
      }
    }, this.recoveryIntervalMs);
  }

  destroy(): void {
    if (this.recoveryTimer) {
      clearInterval(this.recoveryTimer);
      this.recoveryTimer = null;
    }
  }

  get currentTier(): AIProviderTier {
    return this.state.currentTier;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cosine similarity — used by Layer 4 behavioral contracts
// ─────────────────────────────────────────────────────────────────────────────

export function cosineSimilarity(a: number[], b: number[]): number {
  const len = Math.min(a.length, b.length);
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < len; i++) {
    dot += (a[i] ?? 0) * (b[i] ?? 0);
    normA += (a[i] ?? 0) ** 2;
    normB += (b[i] ?? 0) ** 2;
  }
  return dot / (Math.sqrt(normA) * Math.sqrt(normB) || 1);
}

export function cosineDistance(a: number[], b: number[]): number {
  return 1 - cosineSimilarity(a, b);
}
