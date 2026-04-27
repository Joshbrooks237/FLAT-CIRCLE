import { defineConfig } from "tsup";

// Node 18 does not expose the Web Crypto API as a global in ESM/CJS modules.
// This banner injects the globalThis.crypto assignment at the top of each chunk
// so that crypto.randomUUID() resolves correctly on Node >= 18.
const CRYPTO_BANNER = `
import { webcrypto as __webcrypto } from 'node:crypto';
if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = __webcrypto;
}
`;

export default defineConfig({
  entry: {
    index: "src/index.ts",
    types: "src/types.ts",
    "provider-cascade": "src/provider-cascade.ts",
    mod7: "src/mod7.ts",
    pipeline: "src/pipeline.ts",
    "layers/layer2-honeypot": "src/layers/layer2-honeypot.ts",
    "layers/layer8-recursive": "src/layers/layer8-recursive.ts",
    "layers/layer11-merkle": "src/layers/layer11-merkle.ts",
  },
  format: ["esm", "cjs"],
  dts: false,
  clean: true,
  sourcemap: false,
  treeshake: true,
  splitting: true,
  external: ["openai", "@anthropic-ai/sdk"],
  banner: {
    js: CRYPTO_BANNER,
  },
});
