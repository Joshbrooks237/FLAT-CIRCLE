#!/usr/bin/env node
/**
 * flat-circle-proxy CLI
 *
 * Usage:
 *   flat-circle-proxy [--config flat-circle.yaml] [--port 8080]
 */

import { FlatCircleProxy, loadConfig } from "./index.js";

const args = process.argv.slice(2);
const configFlag = args.indexOf("--config");
const configPath = configFlag >= 0 ? args[configFlag + 1] : "flat-circle.yaml";

if (!configPath) {
  console.error("Usage: flat-circle-proxy [--config flat-circle.yaml]");
  process.exit(1);
}

async function main(): Promise<void> {
  console.log(`[Flat Circle] Loading config from ${configPath} ...`);
  const config = await loadConfig(configPath);
  const proxy = new FlatCircleProxy(config);

  proxy.onEvent((event) => {
    if (event.type === "honeypot.triggered" || event.type === "honeypot.recursive.descent") {
      console.log(`[Flat Circle] ${event.type} | ${event.ip} | depth=${event.honeypotDepth ?? 0} | ${event.aiNarration?.slice(0, 80) ?? ""}`);
    } else if (event.type === "provider.failover") {
      console.warn(`[Flat Circle] Provider failover → ${event.providerTier}`);
    } else if (event.type === "merkle.root.updated") {
      console.log(`[Flat Circle] Merkle root updated: ${String(event.metadata["root"]).slice(0, 16)}...`);
    }
  });

  await proxy.listen();
  const port = config.layers.layer13?.listenPort ?? 8080;
  console.log(`[Flat Circle] Proxy listening on :${port}`);
  console.log(`[Flat Circle] Origin: ${config.layers.layer13?.originUrl}`);
  console.log(`[Flat Circle] The frame narrative is active. The interior is hostile.`);
}

main().catch((err) => {
  console.error("[Flat Circle] Fatal:", err);
  process.exit(1);
});
