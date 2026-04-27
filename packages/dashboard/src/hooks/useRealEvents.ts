/**
 * useRealEvents — subscribe to live FlatCircleEvent objects from the proxy SSE stream.
 *
 * When the Flat Circle proxy is running at :8080, it exposes a
 * Server-Sent Events endpoint at GET /flat-circle/stream.
 *
 * This hook connects to that stream and translates raw proxy events into
 * the same ThreatEvent shape the simulated hook produces, so the dashboard
 * displays real traffic without any structural changes.
 *
 * Usage:
 *   const { events, connected } = useRealEvents("http://localhost:8080");
 *
 * When `connected` is false (proxy not running), fall back to simulated data.
 */

import { useState, useEffect, useRef } from "react";
import type { ThreatEvent, AITier, ThreatClass } from "./useSimulatedData";

export interface RealEventsState {
  events: ThreatEvent[];
  connected: boolean;
  proxyUrl: string;
}

const PROXY_DEFAULT = "http://localhost:8080";
const SSE_PATH = "/flat-circle/stream";

function mapProxyEvent(raw: Record<string, unknown>): ThreatEvent | null {
  const type = raw["type"] as string | undefined;
  if (!type || type === "connected") return null;

  // Map proxy EventType to dashboard ThreatEvent["type"]
  const mappedType = type as ThreatEvent["type"];

  const ip = typeof raw["ip"] === "string" ? raw["ip"] : "0.0.0.0";
  const sessionId = typeof raw["sessionId"] === "string" ? raw["sessionId"] : crypto.randomUUID();
  const providerTier = (raw["providerTier"] as AITier | undefined) ?? "static";
  const meta = (raw["metadata"] ?? {}) as Record<string, unknown>;

  const threatClass = typeof meta["threatClass"] === "string"
    ? meta["threatClass"] as ThreatClass
    : undefined;

  const depth = typeof meta["depth"] === "number" ? meta["depth"] : 0;
  const honeypotDepth = typeof raw["honeypotDepth"] === "number" ? raw["honeypotDepth"] : depth;

  const narration = buildNarration(type, ip, sessionId, meta);

  return {
    id: typeof raw["id"] === "string" ? raw["id"] : crypto.randomUUID(),
    type: mappedType,
    timestamp: typeof raw["timestamp"] === "number" ? raw["timestamp"] : Date.now(),
    ip,
    sessionId,
    depth: honeypotDepth,
    threatClass,
    narration,
    providerTier,
  };
}

function buildNarration(
  type: string,
  ip: string,
  sessionId: string,
  meta: Record<string, unknown>
): string {
  const sid = sessionId.slice(0, 8);
  switch (type) {
    case "honeypot.triggered":
      return `${ip} entered honeypot at ${String(meta["path"] ?? "unknown path")}. Session ${sid} flagged.`;
    case "honeypot.recursive.descent":
      return `Session ${sid} at recursive depth ${String(meta["depth"] ?? 0)}. Actor still descending.`;
    case "canary.fired":
      return `Canary token from session ${sid} fired. Unauthorized reuse detected from ${ip}.`;
    case "behavioral.anomaly":
      return `Behavioral contract violation — session ${sid}. Cosine distance exceeded threshold. Rerouting.`;
    case "session.shadowed":
      return `Session ${sid} (${ip}) isolated to shadow environment. Actor continues in the clone.`;
    case "threat.classified":
      return `Session ${sid} classified: ${String(meta["threatClass"] ?? "unknown")}. Score: ${String(meta["sophisticationScore"] ?? "—")}/10.`;
    case "merkle.root.updated":
      return `Merkle root updated. ${String(meta["leafCount"] ?? "?")} leaves. Root: ${String(meta["root"] ?? "").slice(0, 16)}... Chain intact.`;
    case "provider.failover":
      return `AI provider failover → ${String(meta["newTier"] ?? "unknown")}. All layers remain active.`;
    case "campaign.matched":
      return `Probe pattern matched known campaign. Escalating immediately.`;
    case "tarpit.connection.absorbed":
      return `${ip} absorbed into tarpit. Slow-drip response initiated. Connection held open.`;
    case "flood.detected":
      return `Volumetric flood signature from ${ip}. Progressive degradation engaged.`;
    case "upstream.escalated":
      return `Local absorption capacity exceeded. Upstream escalation triggered.`;
    case "dependency.mismatch.detected":
      return `Dependency hash mismatch: ${String(meta["package"] ?? "unknown")}. Supply chain deviation detected.`;
    case "secret.redacted":
      return `Outbound ${String(meta["field"] ?? "field")} contained ${String(meta["patternType"] ?? "credential")} pattern. Redacted before transmission.`;
    case "authn.anomaly.detected":
      return `Authenticated identity ${String(meta["identityId"] ?? sid)} — anomaly detected. Pattern: ${String(meta["anomalyClass"] ?? "unknown")}.`;
    case "dns.record.unrecognized":
      return `DNS record ${String(meta["hostname"] ?? "unknown")} resolves to unrecognized resource.`;
    case "dns.takeover.suspected":
      return `Potential subdomain takeover — ${String(meta["hostname"] ?? "unknown")}. Immediate alert.`;
    case "client.integrity.low":
      return `${ip} scored ${String(meta["score"] ?? "?")} integrity. JA3 mismatch. Routed to honeypot.`;
    case "exfiltration.velocity.exceeded":
      return `Exfiltration velocity threshold crossed for ${String(meta["identityId"] ?? sid)}. Escalating.`;
    case "ai.injection.attempt":
      return `Prompt injection detected in ${String(meta["field"] ?? "input")}. Pattern: ${String(meta["patternType"] ?? "unknown")}. Sanitized.`;
    case "incident.package.sealed":
      return `Session ${sid} sealed as forensic incident package. ${String(meta["leafCount"] ?? "?")} leaves. Signed.`;
    case "compliance.report.generated":
      return `Compliance report generated. Chain of custody continuous and unbroken.`;
    case "legal.hold.activated":
      return `LEGAL HOLD ACTIVATED. Merkle state frozen. Separate immutable record begins.`;
    case "legal.hold.released":
      return `Legal hold released. Frozen record preserved for discovery.`;
    default:
      return `${type} — ${ip} — ${sid}`;
  }
}

export function useRealEvents(proxyUrl: string = PROXY_DEFAULT): RealEventsState {
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const esRef = useRef<EventSource | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let cancelled = false;

    function connect() {
      if (cancelled) return;
      const url = `${proxyUrl}${SSE_PATH}`;
      const es = new EventSource(url);
      esRef.current = es;

      es.onopen = () => {
        if (!cancelled) setConnected(true);
      };

      es.onmessage = (e) => {
        if (cancelled) return;
        try {
          const raw = JSON.parse(e.data) as Record<string, unknown>;
          const event = mapProxyEvent(raw);
          if (event) {
            setEvents((prev) => [event, ...prev.slice(0, 49)]);
          } else if (raw["type"] === "connected") {
            setConnected(true);
          }
        } catch {
          // Malformed event — ignore
        }
      };

      es.onerror = () => {
        es.close();
        esRef.current = null;
        if (!cancelled) {
          setConnected(false);
          // Reconnect after 5 seconds
          reconnectTimer.current = setTimeout(connect, 5_000);
        }
      };
    }

    connect();

    return () => {
      cancelled = true;
      esRef.current?.close();
      esRef.current = null;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };
  }, [proxyUrl]);

  return { events, connected, proxyUrl };
}
