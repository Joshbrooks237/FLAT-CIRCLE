/**
 * Flat Circle Demo App
 *
 * A realistic SaaS-style application. This is the thing Flat Circle protects.
 * It has no security logic of its own. It doesn't need any.
 * Flat Circle is the coat. This is the interior.
 *
 * Run this on port 3000. Point the Flat Circle proxy at localhost:3000.
 * The proxy listens on port 8080. Hit the proxy. Watch the organism.
 *
 * All data is fabricated. None of this is a real application.
 * That is the point — the attacker can't tell the difference.
 */

import { Hono } from "hono";
import { createServer } from "@hono/node-server";

const app = new Hono();

// ─────────────────────────────────────────────────────────────────────────────
// Fake data
// ─────────────────────────────────────────────────────────────────────────────

const USERS = [
  { id: "usr_001", email: "alice@acme.com", role: "admin", plan: "enterprise", createdAt: "2023-01-15" },
  { id: "usr_002", email: "bob@acme.com", role: "member", plan: "pro", createdAt: "2023-03-22" },
  { id: "usr_003", email: "carol@acme.com", role: "member", plan: "pro", createdAt: "2023-07-08" },
  { id: "usr_004", email: "dave@acme.com", role: "viewer", plan: "free", createdAt: "2024-01-03" },
  { id: "usr_005", email: "eve@acme.com", role: "member", plan: "enterprise", createdAt: "2024-02-19" },
];

const PRODUCTS = [
  { id: "prod_001", name: "Starter", price: 0, features: ["5 users", "1 GB storage", "Community support"] },
  { id: "prod_002", name: "Pro", price: 49, features: ["25 users", "50 GB storage", "Email support", "API access"] },
  { id: "prod_003", name: "Enterprise", price: 299, features: ["Unlimited users", "1 TB storage", "Dedicated support", "SSO", "Audit logs"] },
];

const ORDERS = [
  { id: "ord_001", userId: "usr_001", product: "Enterprise", amount: 299, status: "active", renewsAt: "2025-01-15" },
  { id: "ord_002", userId: "usr_002", product: "Pro", amount: 49, status: "active", renewsAt: "2025-03-22" },
  { id: "ord_003", userId: "usr_005", product: "Enterprise", amount: 299, status: "active", renewsAt: "2025-02-19" },
];

// Simple in-memory sessions (demo only)
const SESSIONS = new Map();

function requireAuth(c, next) {
  const token = c.req.header("authorization")?.replace("Bearer ", "");
  if (!token || !SESSIONS.has(token)) {
    return c.json({ error: "Unauthorized", code: "AUTH_REQUIRED" }, 401);
  }
  c.set("user", SESSIONS.get(token));
  return next();
}

function requireAdmin(c, next) {
  const user = c.get("user");
  if (user?.role !== "admin") {
    return c.json({ error: "Forbidden", code: "ADMIN_REQUIRED" }, 403);
  }
  return next();
}

// ─────────────────────────────────────────────────────────────────────────────
// Public routes
// ─────────────────────────────────────────────────────────────────────────────

app.get("/", (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Acme SaaS — The Platform That Scales With You</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0f; color: #e2e8f0; min-height: 100vh; }
    .hero { max-width: 800px; margin: 0 auto; padding: 80px 24px; text-align: center; }
    h1 { font-size: 48px; font-weight: 800; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 16px; }
    p { color: #94a3b8; font-size: 18px; line-height: 1.7; margin-bottom: 32px; }
    .cta { display: inline-flex; gap: 12px; }
    .btn { padding: 12px 28px; border-radius: 8px; font-size: 15px; font-weight: 600; text-decoration: none; cursor: pointer; border: none; }
    .btn-primary { background: #667eea; color: white; }
    .btn-secondary { background: rgba(255,255,255,0.08); color: #e2e8f0; border: 1px solid rgba(255,255,255,0.12); }
    .plans { max-width: 900px; margin: 40px auto; padding: 0 24px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
    .plan { background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 28px; }
    .plan h3 { font-size: 20px; margin-bottom: 8px; }
    .plan .price { font-size: 32px; font-weight: 800; color: #667eea; margin-bottom: 16px; }
    .plan ul { list-style: none; color: #94a3b8; font-size: 14px; line-height: 2; }
    .note { text-align: center; padding: 20px; color: rgba(100,116,139,0.5); font-size: 12px; font-family: monospace; }
  </style>
</head>
<body>
  <div class="hero">
    <h1>The Platform That Scales</h1>
    <p>Acme SaaS gives your team the tools to move fast without breaking things. Built for modern teams who demand reliability, security, and performance.</p>
    <div class="cta">
      <a href="/login" class="btn btn-primary">Get Started</a>
      <a href="/api/products" class="btn btn-secondary">View API</a>
    </div>
  </div>
  <div class="plans">
    ${PRODUCTS.map(p => `
    <div class="plan">
      <h3>${p.name}</h3>
      <div class="price">${p.price === 0 ? "Free" : "$" + p.price + "/mo"}</div>
      <ul>${p.features.map(f => `<li>✓ ${f}</li>`).join("")}</ul>
    </div>`).join("")}
  </div>
  <div class="note">Protected by Flat Circle — twenty-two layers. The interior is hostile.</div>
</body>
</html>`);
});

app.get("/login", (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Sign In — Acme SaaS</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0f; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 40px; width: 100%; max-width: 400px; }
    h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
    p { color: #64748b; font-size: 14px; margin-bottom: 28px; }
    label { display: block; font-size: 13px; font-weight: 500; color: #94a3b8; margin-bottom: 6px; }
    input { width: 100%; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1); color: #e2e8f0; border-radius: 8px; padding: 10px 14px; font-size: 14px; margin-bottom: 16px; outline: none; }
    button { width: 100%; background: #667eea; color: white; border: none; border-radius: 8px; padding: 12px; font-size: 15px; font-weight: 600; cursor: pointer; }
    .hint { margin-top: 16px; font-size: 12px; color: #475569; text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Welcome back</h1>
    <p>Sign in to your Acme account</p>
    <form onsubmit="handleLogin(event)">
      <label>Email</label>
      <input type="email" id="email" placeholder="alice@acme.com" value="alice@acme.com" required />
      <label>Password</label>
      <input type="password" id="password" placeholder="••••••••" value="password123" required />
      <button type="submit">Sign in</button>
    </form>
    <div class="hint">Demo credentials: any @acme.com email / any password</div>
  </div>
  <script>
    async function handleLogin(e) {
      e.preventDefault();
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: document.getElementById('email').value, password: document.getElementById('password').value })
      });
      const data = await res.json();
      if (data.token) {
        localStorage.setItem('token', data.token);
        window.location.href = '/dashboard';
      } else {
        alert(data.error || 'Login failed');
      }
    }
  </script>
</body>
</html>`);
});

app.get("/dashboard", (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Dashboard — Acme SaaS</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0f; color: #e2e8f0; }
    nav { padding: 16px 32px; border-bottom: 1px solid rgba(255,255,255,0.08); display: flex; gap: 24px; align-items: center; }
    nav h1 { font-size: 18px; font-weight: 700; color: #667eea; }
    nav a { color: #64748b; text-decoration: none; font-size: 14px; }
    nav a:hover { color: #e2e8f0; }
    .container { max-width: 1100px; margin: 0 auto; padding: 40px 24px; }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 40px; }
    .card { background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 24px; }
    .card h3 { font-size: 13px; color: #64748b; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.08em; }
    .card .value { font-size: 32px; font-weight: 700; color: #667eea; }
    .section { margin-bottom: 32px; }
    .section h2 { font-size: 18px; font-weight: 600; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; padding: 10px 12px; font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.08em; border-bottom: 1px solid rgba(255,255,255,0.06); }
    td { padding: 12px; font-size: 14px; border-bottom: 1px solid rgba(255,255,255,0.04); }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; background: rgba(102,126,234,0.15); color: #667eea; }
  </style>
</head>
<body>
  <nav>
    <h1>Acme</h1>
    <a href="/dashboard">Dashboard</a>
    <a href="/dashboard/users">Users</a>
    <a href="/dashboard/billing">Billing</a>
    <a href="/admin">Admin</a>
  </nav>
  <div class="container">
    <div class="grid">
      <div class="card"><h3>Total Users</h3><div class="value" id="user-count">—</div></div>
      <div class="card"><h3>Active Subscriptions</h3><div class="value" id="order-count">—</div></div>
      <div class="card"><h3>Monthly Revenue</h3><div class="value" id="revenue">—</div></div>
    </div>
    <div class="section">
      <h2>Recent Users</h2>
      <table>
        <thead><tr><th>Email</th><th>Role</th><th>Plan</th><th>Joined</th></tr></thead>
        <tbody id="users-table"></tbody>
      </table>
    </div>
  </div>
  <script>
    const token = localStorage.getItem('token');
    const headers = token ? { Authorization: 'Bearer ' + token } : {};

    fetch('/api/users', { headers }).then(r => r.json()).then(data => {
      document.getElementById('user-count').textContent = data.users?.length ?? '—';
      const tbody = document.getElementById('users-table');
      (data.users || []).forEach(u => {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td>' + u.email + '</td><td><span class="badge">' + u.role + '</span></td><td>' + u.plan + '</td><td>' + u.createdAt + '</td>';
        tbody.appendChild(tr);
      });
    }).catch(() => {});

    fetch('/api/orders', { headers }).then(r => r.json()).then(data => {
      const orders = data.orders || [];
      document.getElementById('order-count').textContent = orders.length;
      const revenue = orders.reduce((sum, o) => sum + o.amount, 0);
      document.getElementById('revenue').textContent = '$' + revenue.toLocaleString();
    }).catch(() => {});
  </script>
</body>
</html>`);
});

// ─────────────────────────────────────────────────────────────────────────────
// Auth API
// ─────────────────────────────────────────────────────────────────────────────

app.post("/api/auth/login", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const { email, password } = body;

  if (!email || !password) {
    return c.json({ error: "Email and password required" }, 400);
  }

  const user = USERS.find((u) => u.email === email);
  if (!user) {
    // Intentional vagueness — don't confirm the email doesn't exist
    return c.json({ error: "Invalid credentials" }, 401);
  }

  const token = `tok_${crypto.randomUUID().replace(/-/g, "")}`;
  SESSIONS.set(token, user);

  return c.json({
    token,
    user: { id: user.id, email: user.email, role: user.role, plan: user.plan },
    expiresIn: 3600,
  });
});

app.post("/api/auth/logout", (c) => {
  const token = c.req.header("authorization")?.replace("Bearer ", "");
  if (token) SESSIONS.delete(token);
  return c.json({ ok: true });
});

app.get("/api/auth/me", requireAuth, (c) => {
  const user = c.get("user");
  return c.json({ user: { id: user.id, email: user.email, role: user.role, plan: user.plan } });
});

// ─────────────────────────────────────────────────────────────────────────────
// Users API
// ─────────────────────────────────────────────────────────────────────────────

app.get("/api/users", requireAuth, (c) => {
  return c.json({ users: USERS, total: USERS.length });
});

app.get("/api/users/:id", requireAuth, (c) => {
  const user = USERS.find((u) => u.id === c.req.param("id"));
  if (!user) return c.json({ error: "User not found" }, 404);
  return c.json({ user });
});

app.post("/api/users", requireAuth, requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => ({}));
  return c.json({ error: "User creation disabled in demo mode" }, 403);
});

// ─────────────────────────────────────────────────────────────────────────────
// Products API (public)
// ─────────────────────────────────────────────────────────────────────────────

app.get("/api/products", (c) => {
  return c.json({ products: PRODUCTS });
});

app.get("/api/products/:id", (c) => {
  const product = PRODUCTS.find((p) => p.id === c.req.param("id"));
  if (!product) return c.json({ error: "Product not found" }, 404);
  return c.json({ product });
});

// ─────────────────────────────────────────────────────────────────────────────
// Orders API
// ─────────────────────────────────────────────────────────────────────────────

app.get("/api/orders", requireAuth, (c) => {
  const user = c.get("user");
  const orders = user.role === "admin" ? ORDERS : ORDERS.filter((o) => o.userId === user.id);
  return c.json({ orders, total: orders.length });
});

// ─────────────────────────────────────────────────────────────────────────────
// Admin (requires admin role)
// ─────────────────────────────────────────────────────────────────────────────

app.get("/admin", requireAuth, requireAdmin, (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Admin Panel — Acme SaaS</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0f; color: #e2e8f0; }
    nav { padding: 16px 32px; border-bottom: 1px solid rgba(255,100,0,0.2); display: flex; gap: 24px; align-items: center; background: rgba(255,80,0,0.04); }
    nav h1 { font-size: 18px; font-weight: 700; color: #ff6600; }
    .container { max-width: 1100px; margin: 0 auto; padding: 40px 24px; }
    h2 { font-size: 22px; font-weight: 700; margin-bottom: 24px; }
    .alert { background: rgba(255,80,0,0.08); border: 1px solid rgba(255,80,0,0.2); border-radius: 8px; padding: 16px; margin-bottom: 24px; color: #ff8844; font-size: 14px; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; padding: 10px 12px; font-size: 12px; color: #64748b; text-transform: uppercase; border-bottom: 1px solid rgba(255,255,255,0.06); }
    td { padding: 12px; font-size: 14px; border-bottom: 1px solid rgba(255,255,255,0.04); }
  </style>
</head>
<body>
  <nav><h1>⚠ Admin Panel</h1></nav>
  <div class="container">
    <div class="alert">Restricted area. All actions are logged and audited.</div>
    <h2>All Users</h2>
    <table>
      <thead><tr><th>ID</th><th>Email</th><th>Role</th><th>Plan</th><th>Joined</th></tr></thead>
      <tbody>
        ${USERS.map(u => `<tr><td>${u.id}</td><td>${u.email}</td><td>${u.role}</td><td>${u.plan}</td><td>${u.createdAt}</td></tr>`).join("")}
      </tbody>
    </table>
  </div>
</body>
</html>`);
});

app.get("/api/admin/stats", requireAuth, requireAdmin, (c) => {
  const revenue = ORDERS.reduce((sum, o) => sum + o.amount, 0);
  return c.json({
    users: USERS.length,
    orders: ORDERS.length,
    monthlyRevenue: revenue,
    annualRevenue: revenue * 12,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Health / status (monitored by Flat Circle)
// ─────────────────────────────────────────────────────────────────────────────

app.get("/health", (c) => c.json({ status: "ok", version: "1.0.0", uptime: process.uptime() }));

app.get("/api/status", (c) => c.json({
  status: "operational",
  services: { api: "up", database: "up", cache: "up" },
  latencyMs: Math.floor(Math.random() * 30 + 5),
}));

// ─────────────────────────────────────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? "3000", 10);

createServer({ fetch: app.fetch, port: PORT }, () => {
  console.log(`[Demo App] Running on http://localhost:${PORT}`);
  console.log(`[Demo App] Endpoints:`);
  console.log(`           GET  /           — homepage`);
  console.log(`           GET  /login      — login page`);
  console.log(`           GET  /dashboard  — app dashboard`);
  console.log(`           POST /api/auth/login`);
  console.log(`           GET  /api/users  — list users (auth required)`);
  console.log(`           GET  /api/products — public`);
  console.log(`           GET  /admin      — admin panel (admin role)`);
  console.log(`           GET  /health     — health check`);
  console.log(`\n[Demo App] Point Flat Circle proxy at this origin.`);
  console.log(`[Demo App] The interior is real. The coat is Flat Circle.`);
});
