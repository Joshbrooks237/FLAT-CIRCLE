/**
 * Flat Circle — Onion Interior (Layer 1)
 *
 * Composable, stateless middleware pipeline. Each stage is scoped
 * to only its immediate context. No single stage has full visibility
 * into the request lifecycle. Lateral traversal is impossible even
 * if one stage is compromised.
 */

import type {
  LayerContext,
  FlatCircleResponse,
  MiddlewareHandler,
  NextFn,
  FlatCircleRequest,
  Mod7Clocks,
  AIProviderTier,
} from "./types.js";

export type { LayerContext, FlatCircleResponse, MiddlewareHandler, NextFn };

// ─────────────────────────────────────────────────────────────────────────────
// Stage — a single isolated pipeline unit
// ─────────────────────────────────────────────────────────────────────────────

export interface Stage {
  readonly name: string;
  readonly handler: MiddlewareHandler;
  /** Maximum ms this stage may run. If exceeded, it is bypassed. */
  readonly timeoutMs?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline — executes stages in sequence, each in isolation
// ─────────────────────────────────────────────────────────────────────────────

export class Pipeline {
  private readonly stages: Stage[] = [];

  use(stage: Stage): this {
    this.stages.push(stage);
    return this;
  }

  async execute(ctx: LayerContext, response: FlatCircleResponse): Promise<FlatCircleResponse> {
    let index = 0;

    const dispatch = async (): Promise<void> => {
      if (index >= this.stages.length) return;
      const stage = this.stages[index++]!;

      // Each stage receives a frozen snapshot of context — it cannot mutate
      // shared state by accident. Metadata is the only mutable escape hatch.
      const isolatedCtx = isolateContext(ctx);

      const run = stage.handler(isolatedCtx, response, dispatch);

      if (stage.timeoutMs !== undefined) {
        await Promise.race([
          run,
          new Promise<void>((resolve) => setTimeout(resolve, stage.timeoutMs)),
        ]);
      } else {
        await run;
      }

      // Merge any metadata written by the stage back into the parent ctx
      Object.assign(ctx.metadata, isolatedCtx.metadata);
    };

    await dispatch();
    return response;
  }
}

/** Return a shallow-isolated view of context for a single stage. */
function isolateContext(ctx: LayerContext): LayerContext {
  return {
    request: ctx.request,
    sessionId: ctx.sessionId,
    mod7Clocks: ctx.mod7Clocks,
    providerTier: ctx.providerTier,
    isShadowSession: ctx.isShadowSession,
    honeypotDepth: ctx.honeypotDepth,
    metadata: { ...ctx.metadata }, // Separate object — stage mutations don't bleed
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Context factory
// ─────────────────────────────────────────────────────────────────────────────

export function createContext(
  request: FlatCircleRequest,
  clocks: Mod7Clocks,
  providerTier: AIProviderTier,
  isShadowSession = false,
  honeypotDepth = 0
): LayerContext {
  return {
    request,
    sessionId: request.sessionId,
    mod7Clocks: clocks,
    providerTier,
    isShadowSession,
    honeypotDepth,
    metadata: {},
  };
}

export function createResponse(status = 200, body: unknown = null): FlatCircleResponse {
  return { status, headers: {}, body };
}
