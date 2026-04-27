#!/bin/sh
# docker-entrypoint.sh
#
# Allows ORIGIN_URL environment variable to override the originUrl in the
# flat-circle.yaml config at runtime, so the same Docker image works for
# any target application without rebuilding.
#
# Usage:
#   docker run -e ORIGIN_URL=http://myapp:3000 flat-circle-proxy

set -e

CONFIG_FILE="/config/flat-circle.yaml"

if [ -n "$ORIGIN_URL" ]; then
  # Rewrite originUrl in the config file using sed
  sed -i "s|originUrl:.*|originUrl: $ORIGIN_URL|g" "$CONFIG_FILE"
  echo "[Flat Circle] Origin set to: $ORIGIN_URL"
fi

if [ -n "$OPENAI_API_KEY" ]; then
  echo "[Flat Circle] OpenAI provider enabled"
fi

if [ -n "$ANTHROPIC_API_KEY" ]; then
  echo "[Flat Circle] Anthropic provider enabled"
fi

exec "$@"
