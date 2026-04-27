/**
 * @flat-circle/core — Public API
 *
 * Twenty-two layers. Four AI tiers. One philosophy.
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
  Layer14Config,
  Layer15Config,
  Layer16Config,
  Layer17Config,
  AuthAnomalyClass,
  Layer18Config,
  Layer19Config,
  Layer20Config,
  ExfiltrationThresholds,
  Layer21Config,
  Layer22Config,
  ForensicExportTargetType,
  IncidentPackageFormat,
  ComplianceReportFormat,
  ComplianceReportSchedule,
  ForensicExportTargetConfig,
  UpstreamAbsorberConfig,
  UpstreamAbsorberProvider,
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

// Layer 14
export {
  TrafficAbsorptionEngine,
  TarpitEngine,
  FloodSignatureDetector,
  UpstreamAbsorberClient,
} from "./layers/layer14-tarpit.js";
export type {
  TarpitConnection,
  FloodSignature,
  AbsorptionStatus,
  UpstreamAbsorberStatus,
} from "./layers/layer14-tarpit.js";

// Layer 15
export { DependencyIntegrityMonitor } from "./layers/layer15-dependency.js";
export type {
  DependencyIntegrityStatus,
  DependencyEntry,
  DependencyManifest,
  DependencyMismatch,
  IntegrityVerificationResult,
} from "./layers/layer15-dependency.js";

// Layer 16
export { SecretsSentinel, shannonEntropy } from "./layers/layer16-secrets.js";
export type {
  RedactionPatternType,
  RedactionMatch,
  RedactionResult,
  SentinelScanResult,
} from "./layers/layer16-secrets.js";

// Layer 17
export { AuthenticatedAnomalyEngine } from "./layers/layer17-authn-anomaly.js";
export type {
  IdentityProfile,
  AuthnAnomalyEvent,
} from "./layers/layer17-authn-anomaly.js";

// Layer 18
export { DNSIntegrityWatcher } from "./layers/layer18-dns.js";
export type {
  DNSRecordStatus,
  MonitoredDNSRecord,
  DNSScanResult,
} from "./layers/layer18-dns.js";

// Layer 19
export { ClientIntegrityScorer } from "./layers/layer19-client-integrity.js";
export type {
  TLSFingerprint,
  HTTP2Fingerprint,
  ClientIntegrityInput,
  ClientIntegrityScore,
} from "./layers/layer19-client-integrity.js";

// Layer 20
export { ExfiltrationVelocityMonitor } from "./layers/layer20-exfiltration.js";
export type {
  TransferSample,
  IdentityVelocityProfile,
  VelocityCheckResult,
} from "./layers/layer20-exfiltration.js";

// Layer 21
export { AIInputSanitizer, SanitizedProviderCascade } from "./layers/layer21-ai-sanitization.js";
export type {
  InjectionPatternType,
  SanitizationResult,
} from "./layers/layer21-ai-sanitization.js";

// Layer 22
export {
  ForensicExportEngine,
  ForensicStreamExporter,
  IncidentPackageBuilder,
  ComplianceReportGenerator,
  LegalHoldManager,
  ChainOfCustodyVerifier,
  verifySignature,
} from "./layers/layer22-forensic.js";
export type {
  ForensicStreamStatus,
  ForensicLeafRecord,
  IncidentPackage,
  ComplianceReport,
  ComplianceReportInput,
  LegalHold,
  VerificationResult,
} from "./layers/layer22-forensic.js";

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
