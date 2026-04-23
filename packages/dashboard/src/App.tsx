import { useRef } from "react";
import SlimeOrganism from "./components/SlimeOrganism";
import { useSimulatedData } from "./hooks/useSimulatedData";
import type { ThreatEvent, AITier, ThreatClass } from "./hooks/useSimulatedData";

// ─────────────────────────────────────────────────────────────────────────────
// Color helpers
// ─────────────────────────────────────────────────────────────────────────────

function eventColor(type: ThreatEvent["type"]): string {
  switch (type) {
    case "canary.fired":              return "#ff6644";
    case "campaign.matched":          return "#ff4488";
    case "honeypot.recursive.descent": return "#00d060";
    case "honeypot.triggered":        return "#00f07a";
    case "session.shadowed":          return "#88ddaa";
    case "threat.classified":         return "#ffcc44";
    case "behavioral.anomaly":        return "#ffaa00";
    case "provider.failover":         return "#aaaaff";
    case "merkle.root.updated":       return "#44aaff";
    default:                          return "#00f07a";
  }
}

function threatClassLabel(cls: ThreatClass | undefined): string {
  switch (cls) {
    case "nation-state":          return "NATION-STATE";
    case "sophisticated-actor":   return "SOPHISTICATED";
    case "automated-scanner":     return "AUTO-SCANNER";
    case "competitor-scraper":    return "COMPETITOR";
    case "script-kiddie":         return "SCRIPT-KIDDIE";
    default:                      return "UNKNOWN";
  }
}

function threatClassColor(cls: ThreatClass | undefined): string {
  switch (cls) {
    case "nation-state":          return "#cc0033";
    case "sophisticated-actor":   return "#f04a00";
    case "automated-scanner":     return "#f0a500";
    case "competitor-scraper":    return "#ddcc00";
    case "script-kiddie":         return "#00f07a";
    default:                      return "#666";
  }
}

function tierColor(tier: AITier): string {
  switch (tier) {
    case "openai":     return "#00f07a";
    case "anthropic":  return "#4488ff";
    case "ollama":     return "#ffaa00";
    case "static":     return "#ffffff";
  }
}

function tierLabel(tier: AITier): string {
  switch (tier) {
    case "openai":     return "GPT-4o";
    case "anthropic":  return "Claude";
    case "ollama":     return "Ollama";
    case "static":     return "Static";
  }
}

function formatAge(ms: number): string {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Mod 7 Cycle Ring
// ─────────────────────────────────────────────────────────────────────────────

function Mod7Ring({ label, value, color = "#00f07a" }: { label: string; value: number; color?: string }) {
  const r = 16;
  const circumference = 2 * Math.PI * r;
  const filled = (value / 7) * circumference;

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="40" height="40" viewBox="0 0 40 40">
        <circle cx="20" cy="20" r={r} fill="none" stroke="rgba(0,240,122,0.08)" strokeWidth="2.5" />
        <circle
          cx="20" cy="20" r={r}
          fill="none"
          stroke={color}
          strokeWidth="2.5"
          strokeDasharray={`${filled} ${circumference - filled}`}
          strokeDashoffset={circumference / 4}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 3px ${color}66)` }}
        />
        <text x="20" y="25" textAnchor="middle" fill={color} fontSize="11" fontFamily="JetBrains Mono">
          {value}
        </text>
      </svg>
      <span style={{ color: "rgba(0,240,122,0.5)", fontSize: "9px", fontFamily: "JetBrains Mono", letterSpacing: "0.05em" }}>
        {label}
      </span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer status blob
// ─────────────────────────────────────────────────────────────────────────────

function LayerBlob({ id, name, enabled, hitCount, isProxy }: { id: number; name: string; enabled: boolean; hitCount: number; isProxy?: boolean }) {
  const color = enabled ? "#00f07a" : "#1a1a1a";
  const textColor = enabled ? "#00f07a" : "#333";
  const glow = enabled ? "0 0 6px rgba(0,240,122,0.3)" : "none";

  return (
    <div
      className="flex items-center gap-2 px-2 py-1 rounded"
      style={{
        border: `1px solid ${enabled ? "rgba(0,240,122,0.2)" : "rgba(255,255,255,0.04)"}`,
        background: isProxy ? "rgba(0,240,122,0.05)" : "transparent",
        boxShadow: isProxy ? "0 0 0 1px rgba(0,240,122,0.15)" : "none",
      }}
    >
      <div
        className="rounded-full flex-shrink-0"
        style={{
          width: "6px", height: "6px",
          background: color,
          boxShadow: glow,
          animation: enabled && hitCount % 3 === 0 ? "pulse 2s infinite" : "none",
        }}
      />
      <span style={{ color: textColor, fontSize: "10px", fontFamily: "JetBrains Mono", flex: 1 }}>
        {String(id).padStart(2, "0")} {name}
      </span>
      <span style={{ color: "rgba(0,240,122,0.3)", fontSize: "9px", fontFamily: "JetBrains Mono" }}>
        {hitCount.toLocaleString()}
      </span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Shadow session bubble
// ─────────────────────────────────────────────────────────────────────────────

function ShadowBubble({ ip, threatClass, depth, requestCount, startedAt }: {
  ip: string; threatClass: ThreatClass; depth: number; requestCount: number; startedAt: number;
}) {
  return (
    <div
      className="rounded-lg p-3 flex flex-col gap-1"
      style={{
        border: "1px solid rgba(0,240,122,0.08)",
        background: "rgba(0, 10, 5, 0.8)",
        animation: "breathe 6s ease-in-out infinite",
      }}
    >
      <div className="flex items-center justify-between">
        <span style={{ color: threatClassColor(threatClass), fontSize: "9px", letterSpacing: "0.1em", fontFamily: "JetBrains Mono" }}>
          {threatClassLabel(threatClass)}
        </span>
        <span style={{ color: "rgba(0,240,122,0.3)", fontSize: "9px", fontFamily: "JetBrains Mono" }}>
          {formatAge(Date.now() - startedAt)}
        </span>
      </div>
      <span style={{ color: "rgba(0,240,122,0.6)", fontSize: "10px", fontFamily: "JetBrains Mono" }}>{ip}</span>
      <div className="flex gap-3">
        <span style={{ color: "rgba(0,240,122,0.4)", fontSize: "9px", fontFamily: "JetBrains Mono" }}>depth {depth}</span>
        <span style={{ color: "rgba(0,240,122,0.4)", fontSize: "9px", fontFamily: "JetBrains Mono" }}>{requestCount} req</span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main App
// ─────────────────────────────────────────────────────────────────────────────

export default function App() {
  const data = useSimulatedData();
  const feedRef = useRef<HTMLDivElement>(null);

  const nationStateThreat = data.events.slice(0, 5).some(
    (e) => e.threatClass === "nation-state"
  );

  const merkleShort = data.merkle.root.slice(0, 8) + "..." + data.merkle.root.slice(-8);

  return (
    <div
      className="w-screen h-screen overflow-hidden flex flex-col"
      style={{ background: "#000", fontFamily: "'JetBrains Mono', monospace" }}
    >
      {/* ── Header ── */}
      <div
        className="flex items-center justify-between px-6 py-2 flex-shrink-0"
        style={{ borderBottom: "1px solid rgba(0,240,122,0.08)" }}
      >
        <div className="flex items-center gap-4">
          <span
            style={{
              fontFamily: "'DM Serif Display', Georgia, serif",
              fontSize: "20px",
              color: "#00f07a",
              letterSpacing: "0.02em",
              textShadow: "0 0 20px rgba(0,240,122,0.4)",
            }}
          >
            Flat Circle
          </span>
          <div className="flex items-center gap-2">
            <div
              className="rounded-full"
              style={{
                width: "6px", height: "6px",
                background: "#00f07a",
                boxShadow: "0 0 6px #00f07a",
                animation: "pulse 2s infinite",
              }}
            />
            <span style={{ color: "rgba(0,240,122,0.5)", fontSize: "10px" }}>ACTIVE</span>
          </div>
          {data.proxyActive && (
            <div className="flex items-center gap-1">
              <div
                className="rounded-full"
                style={{
                  width: "4px", height: "4px",
                  border: "1px solid rgba(0,240,122,0.6)",
                  animation: "pulse 3s infinite",
                }}
              />
              <span style={{ color: "rgba(0,240,122,0.35)", fontSize: "9px" }}>FRAME NARRATIVE PROXY</span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-6">
          {/* Provider status */}
          <div className="flex items-center gap-2">
            <div
              className="rounded-full"
              style={{
                width: "8px", height: "8px",
                background: tierColor(data.providerTier),
                boxShadow: `0 0 8px ${tierColor(data.providerTier)}66`,
              }}
            />
            <span style={{ color: tierColor(data.providerTier), fontSize: "10px" }}>
              {tierLabel(data.providerTier)}
            </span>
            <span style={{ color: "rgba(0,240,122,0.3)", fontSize: "9px" }}>AI TIER 1</span>
          </div>

          {/* Stats strip */}
          {[
            { label: "HONEYPOT HITS", value: data.stats.honeypotHits.toLocaleString() },
            { label: "SHADOWED", value: data.stats.shadowedSessions },
            { label: "CANARIES", value: data.stats.canariesFired },
            { label: "MERKLE LEAVES", value: data.stats.merkleLeaves.toLocaleString() },
          ].map(({ label, value }) => (
            <div key={label} className="flex flex-col items-end">
              <span style={{ color: "#00f07a", fontSize: "13px", fontWeight: 500 }}>{value}</span>
              <span style={{ color: "rgba(0,240,122,0.3)", fontSize: "8px", letterSpacing: "0.1em" }}>{label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Main body ── */}
      <div className="flex flex-1 min-h-0">

        {/* ── LEFT: Slime organism (2/3 width) ── */}
        <div
          className="flex-1 relative"
          style={{ borderRight: "1px solid rgba(0,240,122,0.06)" }}
        >
          <SlimeOrganism
            slimeEvents={data.slimeEvents}
            providerTier={data.providerTier}
            proxyActive={data.proxyActive}
            shadowSessionCount={data.shadowSessions.length}
            nationStateThreat={nationStateThreat}
          />

          {/* Organism label — barely visible */}
          <div
            className="absolute bottom-4 left-1/2 -translate-x-1/2"
            style={{ color: "rgba(0,240,122,0.12)", fontSize: "9px", letterSpacing: "0.3em" }}
          >
            ORGANISM ACTIVE
          </div>

          {/* Shadow session count indicator */}
          {data.shadowSessions.length > 0 && (
            <div
              className="absolute top-4 left-4"
              style={{ color: "rgba(0,240,122,0.35)", fontSize: "10px" }}
            >
              {data.shadowSessions.length} SHADOWED SESSION{data.shadowSessions.length !== 1 ? "S" : ""}
            </div>
          )}

          {/* Nation-state threat overlay */}
          {nationStateThreat && (
            <div
              className="absolute top-4 right-4 px-2 py-1 rounded"
              style={{
                border: "1px solid rgba(200,0,51,0.4)",
                color: "#cc0033",
                fontSize: "9px",
                letterSpacing: "0.15em",
                animation: "pulse 1s infinite",
              }}
            >
              NATION-STATE PATTERN
            </div>
          )}
        </div>

        {/* ── RIGHT: Event feed + panels (1/3 width) ── */}
        <div
          className="flex flex-col"
          style={{ width: "360px", flexShrink: 0 }}
        >
          {/* AI Threat Feed */}
          <div
            className="flex flex-col flex-1 min-h-0"
            style={{ borderBottom: "1px solid rgba(0,240,122,0.06)" }}
          >
            <div
              className="px-4 py-2 flex-shrink-0"
              style={{ borderBottom: "1px solid rgba(0,240,122,0.06)" }}
            >
              <span style={{ color: "rgba(0,240,122,0.5)", fontSize: "9px", letterSpacing: "0.15em" }}>
                AI THREAT FEED
              </span>
            </div>
            <div
              ref={feedRef}
              className="flex-1 overflow-y-auto px-4 py-2 flex flex-col gap-2"
              style={{ scrollbarWidth: "thin", scrollbarColor: "#003820 #000" }}
            >
              {data.events.slice(0, 20).map((event, i) => (
                <div
                  key={event.id}
                  className="flex flex-col gap-1"
                  style={{
                    animation: i === 0 ? "scrollUp 0.3s ease-out forwards" : "none",
                    borderLeft: `2px solid ${eventColor(event.type)}`,
                    paddingLeft: "8px",
                  }}
                >
                  <div className="flex items-center justify-between">
                    <span
                      style={{
                        color: eventColor(event.type),
                        fontSize: "9px",
                        letterSpacing: "0.1em",
                      }}
                    >
                      {event.type.toUpperCase()}
                    </span>
                    <span style={{ color: "rgba(0,240,122,0.25)", fontSize: "8px" }}>
                      {formatAge(Date.now() - event.timestamp)}
                    </span>
                  </div>
                  <p style={{ color: "rgba(0,240,122,0.7)", fontSize: "10px", lineHeight: "1.5", margin: 0 }}>
                    {event.narration}
                  </p>
                  {event.depth !== undefined && event.depth > 0 && (
                    <span style={{ color: "rgba(0,240,122,0.3)", fontSize: "8px" }}>
                      DEPTH {event.depth} · {event.ip}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Attacker classification */}
          <div style={{ borderBottom: "1px solid rgba(0,240,122,0.06)" }}>
            <div className="px-4 py-2" style={{ borderBottom: "1px solid rgba(0,240,122,0.04)" }}>
              <span style={{ color: "rgba(0,240,122,0.5)", fontSize: "9px", letterSpacing: "0.15em" }}>
                ACTIVE THREATS
              </span>
            </div>
            <div className="px-4 py-2 flex flex-col gap-1">
              {data.events.slice(0, 5).filter((e) => e.threatClass).map((e) => (
                <div key={e.id} className="flex items-center justify-between">
                  <span style={{ color: "rgba(0,240,122,0.5)", fontSize: "9px" }}>{e.ip}</span>
                  <span style={{ color: threatClassColor(e.threatClass), fontSize: "9px", letterSpacing: "0.05em" }}>
                    {threatClassLabel(e.threatClass)}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Shadow sessions */}
          {data.shadowSessions.length > 0 && (
            <div style={{ borderBottom: "1px solid rgba(0,240,122,0.06)" }}>
              <div className="px-4 py-2" style={{ borderBottom: "1px solid rgba(0,240,122,0.04)" }}>
                <span style={{ color: "rgba(0,240,122,0.5)", fontSize: "9px", letterSpacing: "0.15em" }}>
                  SHADOW SESSIONS
                </span>
              </div>
              <div className="px-4 py-2 flex flex-col gap-2">
                {data.shadowSessions.slice(0, 2).map((s) => (
                  <ShadowBubble key={s.id} {...s} />
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Bottom: Merkle + Mod7 + Layer status ── */}
      <div
        className="flex flex-shrink-0 items-stretch"
        style={{
          borderTop: "1px solid rgba(0,240,122,0.08)",
          height: "120px",
        }}
      >
        {/* Merkle root display */}
        <div
          className="flex flex-col justify-center px-6 gap-1"
          style={{ borderRight: "1px solid rgba(0,240,122,0.06)", minWidth: "220px" }}
        >
          <span style={{ color: "rgba(0,240,122,0.35)", fontSize: "8px", letterSpacing: "0.15em" }}>MERKLE ROOT</span>
          <span
            style={{
              color: "#00f07a",
              fontSize: "11px",
              fontFamily: "JetBrains Mono",
              textShadow: "0 0 8px rgba(0,240,122,0.4)",
            }}
          >
            {merkleShort}
          </span>
          <span style={{ color: "rgba(0,240,122,0.3)", fontSize: "8px" }}>
            {data.merkle.leafCount.toLocaleString()} leaves · {formatAge(Date.now() - data.merkle.lastUpdated)}
          </span>
          <div className="flex items-center gap-1 mt-1">
            <div className="rounded-full" style={{ width: "4px", height: "4px", background: "#00f07a" }} />
            <span style={{ color: "#00f07a", fontSize: "8px" }}>INTACT</span>
          </div>
        </div>

        {/* Mod 7 clocks */}
        <div
          className="flex flex-col justify-center px-6 gap-1"
          style={{ borderRight: "1px solid rgba(0,240,122,0.06)" }}
        >
          <span style={{ color: "rgba(0,240,122,0.35)", fontSize: "8px", letterSpacing: "0.15em", marginBottom: "4px" }}>
            MOD 7 RHYTHM
          </span>
          <div className="flex gap-3">
            <Mod7Ring label="HONEY" value={data.mod7.honeypot} />
            <Mod7Ring label="TEMP" value={data.mod7.temporal} />
            <Mod7Ring label="ENTR" value={data.mod7.entropy} />
            <Mod7Ring label="ROUTE" value={data.mod7.routes} />
            <Mod7Ring label="MRKL" value={data.mod7.merkle} />
          </div>
        </div>

        {/* Layer status */}
        <div className="flex-1 px-4 py-2 overflow-hidden">
          <span style={{ color: "rgba(0,240,122,0.35)", fontSize: "8px", letterSpacing: "0.15em" }}>
            THIRTEEN LAYERS
          </span>
          <div className="grid grid-cols-3 gap-x-3 gap-y-1 mt-2">
            {data.layers.map((l) => (
              <LayerBlob
                key={l.id}
                {...l}
                isProxy={l.id === 13}
              />
            ))}
          </div>
        </div>

        {/* Provider + token meter */}
        <div
          className="flex flex-col justify-center px-6 gap-2"
          style={{ borderLeft: "1px solid rgba(0,240,122,0.06)", minWidth: "140px" }}
        >
          <span style={{ color: "rgba(0,240,122,0.35)", fontSize: "8px", letterSpacing: "0.15em" }}>AI PROVIDER</span>
          {(["openai", "anthropic", "ollama", "static"] as AITier[]).map((tier) => {
            const active = tier === data.providerTier;
            return (
              <div key={tier} className="flex items-center gap-2">
                <div
                  className="rounded-full flex-shrink-0"
                  style={{
                    width: "5px", height: "5px",
                    background: active ? tierColor(tier) : "rgba(255,255,255,0.08)",
                    boxShadow: active ? `0 0 6px ${tierColor(tier)}` : "none",
                  }}
                />
                <span
                  style={{
                    color: active ? tierColor(tier) : "rgba(255,255,255,0.15)",
                    fontSize: "9px",
                    fontFamily: "JetBrains Mono",
                  }}
                >
                  {tierLabel(tier)}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
