/**
 * Static Fallback Library — Tier 4 of the AI provider cascade.
 *
 * Pre-generated convincing decoy content.
 * Zero model inference. Zero latency. Always available.
 */

export const STATIC_DECOY_LIBRARY = {
  credentials: [
    JSON.stringify({
      users: [
        { id: 1, username: "admin", password_hash: "$2b$12$hKxP9QzV8mN3kJwR5tYuAeQm1nBvCdEf7gHiJkLmNoPqRsTuVwXy", role: "superadmin", mfa_secret: "JBSWY3DPEHPK3PXP" },
        { id: 2, username: "sysop", password_hash: "$2b$12$dGkL7nMqP4rS9tUvWxYzAaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPp", role: "operator" },
        { id: 3, username: "api_service", api_key: "sk-live-xK9mN2pQ7rT4vW1y3B6cE8fH0jL5n", permissions: ["read", "write"] },
      ],
      db_credentials: { host: "db-prod-1.internal", port: 5432, database: "production", username: "app_user", password: "Xk9$mN2pQ7#rT4vW" },
    }, null, 2),
    JSON.stringify({
      secrets: {
        jwt_secret: "HS512-secret-xK9mN2pQ7rT4vW1y3B6cE8fH0jL5nMqPsRtUv",
        encryption_key: "AES256-key-Xk9mN2pQ7rT4vW1y3B6cE8fH0jL5nMq",
        session_secret: "sess-xK9mN2pQ7rT4vW1y3B6cE8f",
        payment_key: "decoy_xK9mN2pQ7rT4vW1y3B6cE8fH0jL5nMqPsRtUvWxYzAa",
        cloud_access_key: "DECOY_IOSFODNN7EXAMPLE_NOT_REAL",
        cloud_secret_key: "DECOY/K7MDENG/bPxRfiCYNOT_A_REAL_KEY_EXAMPLE",
      },
    }, null, 2),
  ],

  apiSchemas: [
    JSON.stringify({
      openapi: "3.1.0",
      info: { title: "Internal Admin API", version: "4.2.1", description: "Internal administration endpoints" },
      paths: {
        "/api/v4/admin/users": {
          get: { summary: "List all users", security: [{ bearerAuth: [] }], parameters: [{ name: "include_deleted", in: "query", schema: { type: "boolean" } }] },
          post: { summary: "Create user", requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/UserCreate" } } } } },
        },
        "/api/v4/admin/secrets": {
          get: { summary: "List secret keys", security: [{ adminOnly: [] }] },
        },
        "/api/v4/admin/database/export": {
          post: { summary: "Export database snapshot", description: "Streams a full PostgreSQL dump" },
        },
      },
    }, null, 2),
    JSON.stringify({
      graphql: true,
      schema: `
        type Query {
          users(filter: UserFilter, limit: Int, offset: Int): [User!]!
          user(id: ID!): User
          adminStats: AdminStats!
          exportData(format: ExportFormat!): DataExport!
        }
        type User {
          id: ID!
          email: String!
          passwordHash: String!
          role: UserRole!
          apiKeys: [ApiKey!]!
          sessions: [Session!]!
        }
        type AdminStats {
          totalRevenue: Float!
          activeUsers: Int!
          databaseSize: String!
        }
      `,
    }, null, 2),
  ],

  adminPanels: [
    `<!DOCTYPE html><html><head><title>Admin Panel — v4.2.1</title></head><body>
<h1>System Administration</h1>
<nav>
  <a href="/admin/users">User Management</a> |
  <a href="/admin/database">Database</a> |
  <a href="/admin/logs">Audit Logs</a> |
  <a href="/admin/secrets">API Keys</a> |
  <a href="/admin/backup">Backup & Export</a>
</nav>
<p>Logged in as: sysadmin@internal | Session expires: 8h</p>
</body></html>`,
  ],

  generic: [
    JSON.stringify({ status: "ok", version: "4.2.1", environment: "production", uptime: 847293, features: { admin: true, api: true, webhooks: true } }),
    JSON.stringify({ error: null, data: { internal_id: "svc-xK9mN2pQ7", region: "us-east-1", cluster: "prod-k8s-02" } }),
    JSON.stringify({ message: "Success", timestamp: Date.now(), trace_id: crypto.randomUUID() }),
  ],
};

/** Pre-computed static embedding clusters for behavioral contract baseline.  */
export const STATIC_EMBEDDINGS = {
  normalWebTraffic: Array.from({ length: 384 }, (_, i) => Math.sin(i * 0.1) * 0.3),
  botTraffic: Array.from({ length: 384 }, (_, i) => Math.cos(i * 0.05) * 0.5),
  scannerTraffic: Array.from({ length: 384 }, (_, i) => Math.tan(i * 0.02) * 0.1),
};
