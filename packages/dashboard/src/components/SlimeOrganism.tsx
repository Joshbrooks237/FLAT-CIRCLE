import { useRef, useEffect, useCallback } from "react";
import type { SlimeEvent, AITier } from "../hooks/useSimulatedData";

interface Props {
  slimeEvents: SlimeEvent[];
  providerTier: AITier;
  proxyActive: boolean;
  shadowSessionCount: number;
  nationStateThreat: boolean;
}

interface Particle {
  id: number;
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  opacity: number;
  hostile: boolean;
  caught: boolean;
  catchTime: number;
}

interface MerkleNode {
  x: number;
  y: number;
  parentX: number;
  parentY: number;
  depth: number;
  glow: number;
  glowDir: number;
}

const TIER_ALPHA: Record<AITier, number> = {
  openai:    1.0,
  anthropic: 0.82,
  ollama:    0.65,
  static:    0.45,
};

export default function SlimeOrganism({ slimeEvents, providerTier, proxyActive, shadowSessionCount, nationStateThreat }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<Particle[]>([]);
  const merkleNodesRef = useRef<MerkleNode[]>([]);
  const frameRef = useRef<number>(0);
  const timeRef = useRef<number>(0);
  const rippleRef = useRef<Array<{ x: number; y: number; r: number; maxR: number; alpha: number; type: string }>>([]);
  const particleIdRef = useRef(0);

  // Build Merkle tree visualization
  const buildMerkleTree = useCallback((w: number, h: number) => {
    const nodes: MerkleNode[] = [];
    const levels = 5;
    const rootX = w * 0.5;
    const rootY = h * 0.88;

    function addNode(x: number, y: number, px: number, py: number, depth: number, maxDepth: number) {
      nodes.push({ x, y, parentX: px, parentY: py, depth, glow: Math.random(), glowDir: Math.random() > 0.5 ? 1 : -1 });
      if (depth < maxDepth) {
        const spread = (w * 0.35) / Math.pow(2, depth);
        const dy = (h * 0.12);
        addNode(x - spread, y - dy, x, y, depth + 1, maxDepth);
        addNode(x + spread, y - dy, x, y, depth + 1, maxDepth);
      }
    }
    addNode(rootX, rootY, rootX, rootY, 0, levels);
    merkleNodesRef.current = nodes;
  }, []);

  const spawnParticle = useCallback((w: number, h: number, hostile = true) => {
    const edge = Math.floor(Math.random() * 4);
    let x = 0, y = 0;
    if (edge === 0) { x = Math.random() * w; y = 0; }
    else if (edge === 1) { x = w; y = Math.random() * h; }
    else if (edge === 2) { x = Math.random() * w; y = h; }
    else { x = 0; y = Math.random() * h; }

    const cx = w * 0.5, cy = h * 0.45;
    const angle = Math.atan2(cy - y, cx - x) + (Math.random() - 0.5) * 0.6;
    const speed = hostile ? (Math.random() * 0.4 + 0.2) : (Math.random() * 0.15 + 0.05);

    particlesRef.current.push({
      id: particleIdRef.current++,
      x, y,
      vx: Math.cos(angle) * speed,
      vy: Math.sin(angle) * speed,
      radius: hostile ? (Math.random() * 2 + 1) : (Math.random() * 1 + 0.5),
      opacity: hostile ? (Math.random() * 0.6 + 0.3) : (Math.random() * 0.2 + 0.05),
      hostile,
      caught: false,
      catchTime: 0,
    });

    if (particlesRef.current.length > 60) {
      particlesRef.current = particlesRef.current.slice(-60);
    }
  }, []);

  // Handle slime events → ripples
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const latest = slimeEvents[slimeEvents.length - 1];
    if (!latest) return;

    const w = canvas.width;
    const h = canvas.height;
    const x = (latest.x / 100) * w;
    const y = (latest.y / 100) * h;

    if (latest.type === "ripple") {
      rippleRef.current.push({ x, y, r: 0, maxR: 80, alpha: 0.8, type: "ripple" });
      spawnParticle(w, h, true);
    } else if (latest.type === "flare") {
      rippleRef.current.push({ x, y, r: 0, maxR: 120, alpha: 1.0, type: "flare" });
    } else if (latest.type === "darken") {
      rippleRef.current.push({ x, y, r: 0, maxR: 60, alpha: 0.6, type: "darken" });
    } else if (latest.type === "ring") {
      rippleRef.current.push({ x: w * 0.5, y: h * 0.45, r: 0, maxR: Math.max(w, h) * 0.55, alpha: 0.5, type: "ring" });
    }
  }, [slimeEvents, spawnParticle]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      canvas.width = canvas.offsetWidth * window.devicePixelRatio;
      canvas.height = canvas.offsetHeight * window.devicePixelRatio;
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
      buildMerkleTree(canvas.offsetWidth, canvas.offsetHeight);
    };

    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    // Spawn legit traffic passthrough particles
    const legit = setInterval(() => spawnParticle(canvas.offsetWidth, canvas.offsetHeight, false), 3000);
    // Spawn hostile probes
    const hostile = setInterval(() => spawnParticle(canvas.offsetWidth, canvas.offsetHeight, true), 1800);

    const render = (timestamp: number) => {
      const dt = timestamp - timeRef.current;
      timeRef.current = timestamp;
      const w = canvas.offsetWidth;
      const h = canvas.offsetHeight;
      const cx = w * 0.5;
      const cy = h * 0.45;

      ctx.clearRect(0, 0, w, h);

      const tierAlpha = TIER_ALPHA[providerTier] ?? 1.0;
      const threatMult = nationStateThreat ? 1.4 : 1.0;
      const shadowMult = 1 + shadowSessionCount * 0.08;

      // ── Merkle root system (background, barely visible) ──
      for (const node of merkleNodesRef.current) {
        node.glow += node.glowDir * 0.003;
        if (node.glow > 1 || node.glow < 0) node.glowDir *= -1;

        // Draw branch
        if (node.depth > 0) {
          const alpha = (0.03 + node.glow * 0.04) * tierAlpha;
          ctx.beginPath();
          ctx.moveTo(node.x, node.y);
          ctx.lineTo(node.parentX, node.parentY);
          ctx.strokeStyle = `rgba(0, 240, 122, ${alpha})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }

        // Draw node
        const nodeAlpha = (0.05 + node.glow * 0.1) * tierAlpha;
        ctx.beginPath();
        ctx.arc(node.x, node.y, 1.5 - node.depth * 0.2, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 240, 122, ${nodeAlpha})`;
        ctx.fill();
      }

      // ── Main slime organism body ──
      const t = timestamp / 1000;
      const breathe = 1 + Math.sin(t * 0.8) * 0.012;
      const rx = (w * 0.35 + Math.sin(t * 0.3) * 5) * breathe;
      const ry = (h * 0.32 + Math.cos(t * 0.5) * 4) * breathe;

      // Outer glow (proxy ring when active)
      if (proxyActive) {
        const ringPulse = 0.5 + Math.sin(t * 0.6) * 0.2;
        const gradient = ctx.createRadialGradient(cx, cy, rx * 0.95, cx, cy, rx * 1.15);
        gradient.addColorStop(0, `rgba(0, 240, 122, 0)`);
        gradient.addColorStop(0.5, `rgba(0, 240, 122, ${0.04 * ringPulse * tierAlpha})`);
        gradient.addColorStop(1, `rgba(0, 240, 122, 0)`);
        ctx.beginPath();
        ctx.ellipse(cx, cy, rx * 1.15, ry * 1.15, 0, 0, Math.PI * 2);
        ctx.fillStyle = gradient;
        ctx.fill();

        ctx.beginPath();
        ctx.ellipse(cx, cy, rx * 1.12, ry * 1.12, 0, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(0, 240, 122, ${0.08 * ringPulse * tierAlpha})`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      // Main body fill
      const bodyAlpha = (0.12 + Math.sin(t * 0.9) * 0.02) * tierAlpha * shadowMult;
      const shadowAlpha = Math.min(shadowMult - 1, 0.15);
      ctx.beginPath();
      ctx.ellipse(cx, cy, rx, ry, 0, 0, Math.PI * 2);
      const bodyGrad = ctx.createRadialGradient(cx - rx * 0.2, cy - ry * 0.2, 0, cx, cy, rx);
      bodyGrad.addColorStop(0, `rgba(0, 240, 122, ${bodyAlpha * 1.5 * threatMult})`);
      bodyGrad.addColorStop(0.6, `rgba(0, 200, 100, ${bodyAlpha * threatMult})`);
      bodyGrad.addColorStop(1, `rgba(0, 100, 50, ${bodyAlpha * 0.3})`);
      ctx.fillStyle = bodyGrad;
      ctx.fill();

      // Shadow darkening overlay
      if (shadowMult > 1) {
        ctx.beginPath();
        ctx.ellipse(cx, cy, rx, ry, 0, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 20, 10, ${shadowAlpha})`;
        ctx.fill();
      }

      // Threat color tint
      if (nationStateThreat) {
        ctx.beginPath();
        ctx.ellipse(cx, cy, rx * 0.7, ry * 0.7, 0, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(200, 0, 50, ${0.04 * (0.5 + Math.sin(t * 2) * 0.3)})`;
        ctx.fill();
      }

      // Body edge / membrane
      ctx.beginPath();
      ctx.ellipse(cx, cy, rx, ry, 0, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(0, 240, 122, ${0.25 * tierAlpha})`;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Inner membrane shimmer
      const shimmerT = Math.sin(t * 1.2) * 0.5 + 0.5;
      ctx.beginPath();
      ctx.ellipse(cx, cy, rx * 0.75, ry * 0.75, 0, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(0, 240, 122, ${0.06 * shimmerT * tierAlpha})`;
      ctx.lineWidth = 0.5;
      ctx.stroke();

      // ── Ripple events ──
      rippleRef.current = rippleRef.current.filter((r) => r.alpha > 0.01);
      for (const rip of rippleRef.current) {
        const speed = rip.type === "ring" ? 1.5 : 1.2;
        rip.r += speed;
        rip.alpha -= rip.type === "ring" ? 0.006 : 0.015;

        const color = rip.type === "flare"  ? "0, 255, 150" :
                      rip.type === "darken" ? "0, 60, 30"   :
                      rip.type === "ring"   ? "0, 240, 122" :
                                              "0, 240, 122";

        ctx.beginPath();
        ctx.ellipse(rip.x, rip.y, rip.r, rip.r * 0.6, 0, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(${color}, ${rip.alpha * tierAlpha})`;
        ctx.lineWidth = rip.type === "flare" ? 2 : 1;
        ctx.stroke();
      }

      // ── Particles ──
      particlesRef.current = particlesRef.current.filter((p) => {
        if (p.caught) return Date.now() - p.catchTime < 1500;
        return p.opacity > 0.02;
      });

      for (const p of particlesRef.current) {
        if (!p.caught) {
          p.x += p.vx;
          p.y += p.vy;

          // Check if hostile particle hit the slime surface
          const dx = (p.x - cx) / rx;
          const dy = (p.y - cy) / ry;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (p.hostile && dist <= 1.05) {
            // Particle caught by slime
            p.caught = true;
            p.catchTime = Date.now();
            p.vx = 0;
            p.vy = 0;
          }

          // Legit traffic passes through
          if (!p.hostile && (p.x < 0 || p.x > w || p.y < 0 || p.y > h)) {
            p.opacity = 0;
          }
        }

        const color = p.caught ? "255, 60, 60"
          : p.hostile ? "20, 20, 20"
          : "0, 240, 122";
        const pAlpha = p.caught
          ? Math.max(0, 1 - (Date.now() - p.catchTime) / 1500) * 0.7
          : p.opacity * (p.hostile ? 1 : 0.4);

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${color}, ${pAlpha * tierAlpha})`;
        ctx.fill();
      }

      // ── Provider tier luminance indicator (subtle dim effect) ──
      if (tierAlpha < 1) {
        ctx.beginPath();
        ctx.ellipse(cx, cy, rx * 1.2, ry * 1.2, 0, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 0, 0, ${(1 - tierAlpha) * 0.3})`;
        ctx.fill();
      }

      frameRef.current = requestAnimationFrame(render);
    };

    frameRef.current = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(frameRef.current);
      clearInterval(legit);
      clearInterval(hostile);
      ro.disconnect();
    };
  }, [providerTier, proxyActive, shadowSessionCount, nationStateThreat, buildMerkleTree, spawnParticle]);

  return (
    <canvas
      ref={canvasRef}
      className="w-full h-full"
      style={{ display: "block" }}
    />
  );
}
