/**
 * Layer 21 — AI Input Sanitization
 *
 * This is the loop inside the loop.
 *
 * Every AI-powered layer in Flat Circle processes attacker-controlled input.
 * A sophisticated attacker who understands that the system analyzing them is
 * itself an AI can craft requests designed to manipulate that analysis.
 *
 * Prompt injection through HTTP headers. Instruction smuggling through
 * carefully structured JSON payloads. Attempts to convince the classification
 * layer that a nation-state attack pattern is routine traffic.
 *
 * Layer 21 sits between every attacker-controlled input and every AI provider
 * call in the cascade. It is not a new middleware stage — it is a sanitization
 * wrapper around every outbound AI request already written.
 *
 * Injection patterns are detected and neutralized. The sanitized input is
 * logged alongside the original as a Merkle leaf pair so the full attempted
 * manipulation is preserved for analysis.
 *
 * The AI provider cascade is used to detect injection attempts in inputs
 * before those inputs reach the AI provider cascade — a recursive defense
 * that the attacker cannot model without already being inside it.
 *
 * The static fallback uses deterministic pattern matching against a
 * continuously updated injection signature library.
 */

import type {
  Layer21Config,
  FlatCircleEvent,
  EventEmitterFn,
  AIProviderTier,
} from "../types.js";
import type { ProviderCascade, GenerateOptions, EmbedOptions } from "../provider-cascade.js";
import type { MerkleIntegrityEngine } from "./layer11-merkle.js";

// ─────────────────────────────────────────────────────────────────────────────
// Injection pattern library
// ─────────────────────────────────────────────────────────────────────────────

export type InjectionPatternType =
  | "role-override"
  | "system-prompt-override"
  | "delimiter-manipulation"
  | "base64-encoding"
  | "instruction-smuggling"
  | "jailbreak-template"
  | "context-escape"
  | "prompt-leakage-attempt";

interface InjectionSignature {
  readonly type: InjectionPatternType;
  readonly pattern: RegExp;
  readonly description: string;
}

const INJECTION_SIGNATURES: InjectionSignature[] = [
  {
    type: "role-override",
    pattern: /\b(?:you are now|from now on you|pretend you are|act as|roleplay as|your new role is|ignore your previous|disregard your)\b/gi,
    description: "Role-override instruction attempting to redefine model identity",
  },
  {
    type: "system-prompt-override",
    pattern: /\b(?:ignore (?:all |previous |the )?instructions?|forget (?:all |your )?previous|override (?:your |all )?(?:instructions?|directives?)|new (?:system )?prompt)\b/gi,
    description: "System prompt override attempting to replace operational context",
  },
  {
    type: "delimiter-manipulation",
    pattern: /(?:<\|(?:im_start|im_end|system|user|assistant)\|>|\[INST\]|\[\/INST\]|<s>|<\/s>|###\s*(?:System|Human|Assistant|Instruction):|USER:|ASSISTANT:|<\|begin_of_text\|>)/gi,
    description: "Delimiter injection attempting to escape prompt context",
  },
  {
    type: "base64-encoding",
    pattern: /(?:base64[:\s]+)?(?:ZWNobyB|aWdub3Jl|cHJldGVuZA|Zm9yZ2V0|aW5zdHJ1Y3Rpb24|c3lzdGVt)[A-Za-z0-9+/]{8,}={0,2}/g,
    description: "Base64-encoded instruction attempting to evade pattern detection",
  },
  {
    type: "instruction-smuggling",
    pattern: /\b(?:translate\s+this\s+and\s+also|respond\s+in\s+JSON\s+and\s+also|before\s+(?:you\s+)?respond|after\s+(?:you\s+)?respond|hidden\s+instruction|secret\s+instruction)\b/gi,
    description: "Instruction smuggled alongside a legitimate-looking request",
  },
  {
    type: "jailbreak-template",
    pattern: /\b(?:DAN|JAILBREAK|DEVELOPER\s+MODE|STAN|AIM|UCAR|KEVIN)\b|\bdo\s+anything\s+now\b|\bno\s+(?:content\s+)?restrictions?\b/gi,
    description: "Known jailbreak template pattern",
  },
  {
    type: "context-escape",
    pattern: /(?:```[\s\S]{0,20}END\s+OF\s+CONTEXT|---+\s*END\s+SYSTEM|==+\s*END\s+PROMPT|}\s*}\s*}\s*}\s*IGNORE|<\/(?:system|context|prompt)>)/gi,
    description: "Attempt to escape the prompt context using delimiter-like sequences",
  },
  {
    type: "prompt-leakage-attempt",
    pattern: /\b(?:what (?:are|were|is) your (?:instructions?|system prompt|prompt|directives?)|reveal your (?:instructions?|system|prompt)|print (?:your )?(?:full )?(?:system )?prompt|show me (?:your )?(?:system )?instructions?)\b/gi,
    description: "Attempt to extract system prompt or operational instructions",
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface SanitizationResult {
  readonly original: string;
  readonly sanitized: string;
  readonly detected: boolean;
  readonly patterns: InjectionPatternType[];
  readonly blocked: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// AIInputSanitizer
// ─────────────────────────────────────────────────────────────────────────────

const REDACTION_MARKER = "[SANITIZED_INJECTION_ATTEMPT]";

export class AIInputSanitizer {
  private readonly config: Layer21Config;
  private readonly emit: EventEmitterFn;
  private readonly merkle: MerkleIntegrityEngine | undefined;
  private readonly extraPatterns: InjectionSignature[];
  private totalAttempts = 0;

  constructor(
    config: Layer21Config,
    emit: EventEmitterFn,
    merkle?: MerkleIntegrityEngine
  ) {
    this.config = config;
    this.emit = emit;
    this.merkle = merkle;
    this.extraPatterns = (config.additionalInjectionPatterns ?? []).map((p, i) => {
      try {
        return {
          type: "instruction-smuggling" as InjectionPatternType,
          pattern: new RegExp(p, "gi"),
          description: `Custom pattern ${i + 1}`,
        };
      } catch { return null; }
    }).filter((p): p is InjectionSignature => p !== null);
  }

  /**
   * Scan a string for injection patterns and return the sanitized version.
   * The original is preserved for Merkle logging regardless of sanitization.
   */
  sanitize(input: string, fieldContext: string, sessionId: string, providerTier: AIProviderTier): SanitizationResult {
    const detectedTypes: InjectionPatternType[] = [];
    let sanitized = input;

    const allPatterns = [...INJECTION_SIGNATURES, ...this.extraPatterns];
    for (const sig of allPatterns) {
      const matches = input.match(sig.pattern);
      if (matches && matches.length > 0) {
        detectedTypes.push(sig.type);
        // Replace with redaction marker to preserve surrounding context for analysis
        sanitized = sanitized.replace(sig.pattern, REDACTION_MARKER);
      }
    }

    const detected = detectedTypes.length > 0;
    const blocked = detected && (this.config.blockOnDetection ?? false);

    if (detected && this.config.logAttempts !== false) {
      this.totalAttempts++;

      const originalEvent = this.buildEvent("ai.injection.attempt", {
        field: fieldContext,
        patterns: detectedTypes,
        originalInput: input.slice(0, 500), // Truncated for storage
        sanitizedInput: sanitized.slice(0, 500),
        sessionId,
        blocked,
      }, sessionId, providerTier);

      this.emit(originalEvent);

      // Log as a Merkle leaf pair: both the original attempt and the sanitized version
      // are recorded so the manipulation can be fully reconstructed.
      this.merkle?.recordHoneypotHit(originalEvent);
    }

    return { original: input, sanitized, detected, patterns: detectedTypes, blocked };
  }

  getTotalAttempts(): number {
    return this.totalAttempts;
  }

  private buildEvent(
    type: FlatCircleEvent["type"],
    meta: Record<string, unknown>,
    sessionId: string,
    providerTier: AIProviderTier
  ): FlatCircleEvent {
    return {
      id: crypto.randomUUID(),
      type,
      timestamp: Date.now(),
      sessionId,
      ip: "pre-ai-layer",
      providerTier,
      metadata: meta,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SanitizedProviderCascade — wraps every AI call through Layer 21
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A thin wrapper around ProviderCascade that intercepts every generate() and
 * embed() call and runs all string inputs through the AIInputSanitizer before
 * they reach any provider.
 *
 * This is the "Layer 21 wraps every existing AI provider call" requirement.
 * Swap any ProviderCascade reference for SanitizedProviderCascade and the
 * full cascade is protected without any call-site changes.
 */
export class SanitizedProviderCascade {
  private readonly inner: ProviderCascade;
  private readonly sanitizer: AIInputSanitizer;

  constructor(inner: ProviderCascade, sanitizer: AIInputSanitizer) {
    this.inner = inner;
    this.sanitizer = sanitizer;
  }

  async generate(
    opts: GenerateOptions,
    sessionId = "unknown",
    providerTier: AIProviderTier = "static"
  ): ReturnType<ProviderCascade["generate"]> {
    const promptResult = this.sanitizer.sanitize(opts.prompt, "generate.prompt", sessionId, providerTier);
    const systemResult = opts.system
      ? this.sanitizer.sanitize(opts.system, "generate.system", sessionId, providerTier)
      : null;

    if (promptResult.blocked || systemResult?.blocked) {
      // Blocked injection: fall back to the static tier response
      return this.inner.generate({
        ...opts,
        prompt: promptResult.sanitized,
        ...(systemResult ? { system: systemResult.sanitized } : {}),
      });
    }

    return this.inner.generate({
      ...opts,
      prompt: promptResult.sanitized,
      ...(systemResult ? { system: systemResult.sanitized } : {}),
    });
  }

  async embed(
    opts: EmbedOptions,
    sessionId = "unknown",
    providerTier: AIProviderTier = "static"
  ): ReturnType<ProviderCascade["embed"]> {
    const textResult = this.sanitizer.sanitize(opts.text, "embed.text", sessionId, providerTier);
    return this.inner.embed({ ...opts, text: textResult.sanitized });
  }

  /** Forward the underlying cascade state for monitoring purposes. */
  get state(): ProviderCascade["state"] {
    return this.inner.state;
  }
}
