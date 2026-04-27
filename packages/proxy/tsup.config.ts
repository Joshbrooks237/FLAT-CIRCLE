import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    cli: "src/cli.ts",
  },
  format: ["esm"],
  outDir: "dist",
  dts: false,
  clean: true,
  sourcemap: false,
  splitting: true,
  treeshake: true,
  external: ["hono", "@hono/node-server", "js-yaml"],
});
