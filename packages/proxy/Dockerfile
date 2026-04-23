FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json pnpm-workspace.yaml ./
COPY packages/core/package.json ./packages/core/
COPY packages/proxy/package.json ./packages/proxy/
RUN npm install -g pnpm && pnpm install --frozen-lockfile
COPY packages/core ./packages/core
COPY packages/proxy ./packages/proxy
RUN pnpm run build

FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/packages/proxy/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
EXPOSE 8080
CMD ["node", "dist/cli.js", "--config", "/config/flat-circle.yaml"]
