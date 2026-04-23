/**
 * @flat-circle/core — Public API
 *
 * Thirteen layers. Four AI tiers. One philosophy.
 */

// Types
export type {
  FlatCircleConfig,
  LayerConfig,
  AIProviderConfig,
  OpenAIProviderConfig,
  AnthropicProviderConfig,
  OllamaProviderConfig,
  StaticFallbackConfig,
  AIProviderTier,
  Layer1Config,
  Layer2Config,
  Layer3Config,
  Layer4Config,
  Layer5Config,
  Layer6Config,
  Layer7Config,
  Layer8Config,
  Layer9Config,
  Layer10Config,
  Layer11Config,
  Layer12Config,
  Layer13Config,
  FlatCircleRequest,
  FlatCircleResponse,
  LayerContext,
  MiddlewareHandler,
  NextFn,
  FlatCircleEvent,
  EventEmitterFn,
  EventType,
  ThreatClass,
  HoneypotRoute,
  Mod7Clocks,
  HttpMethod,
  LogLevel,
  FingerprintPersona,
  ProxyDeployTarget,
  StorageAdapterConfig,
  AlertingConfig,
  DashboardConfig,
} from "./types.js";

// Provider cascade
export { ProviderCascade, cosineSimilarity, cosineDistance } from "./provider-cascade.js";
export type { AIProvider, GenerateOptions, EmbedOptions, CascadeState } from "./provider-cascade.js";

// Mod 7 rhythm
export {
  computeMod7Clocks,
  honeypotClock,
  temporalClock,
  entropyClock,
  routesClock,
  merkleClock,
  activeHoneypotSlots,
  ghostHeaderCount,
  validateTemporalGate,
} from "./mod7.js";
export type { Mod7ClockInput } from "./mod7.js";

// Pipeline / Layer 1
export { Pipeline, createContext, createResponse } from "./pipeline.js";
export type { Stage } from "./pipeline.js";

// Layer 2
export { HoneypotMesh } from "./layers/layer2-honeypot.js";

// Layer 8
export { RecursiveHoneypot } from "./layers/layer8-recursive.js";

// Layer 11
export {
  MerkleIntegrityEngine,
  MerkleSessionTree,
  computeRoot,
  verifyProof,
  computeProof,
  issueCanaryToken,
} from "./layers/layer11-merkle.js";
export type { MerkleLeaf, MerkleRootSnapshot, CanaryToken, ProofNode, LeafKind } from "./layers/layer11-merkle.js";
