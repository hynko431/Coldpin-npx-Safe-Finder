# syntax=docker/dockerfile:1
# Coldpin zero-dependency Node.js 24 CLI & MCP Server container image
# Published to GitHub Container Registry: ghcr.io/hynko431/coldpin

FROM node:24-alpine

LABEL org.opencontainers.image.title="Coldpin" \
      org.opencontainers.image.description="Zero-execution npx/npm discovery, static malware triage, tarball-to-source parity, clean-anchor recovery, and local/HTTP MCP server." \
      org.opencontainers.image.url="https://coldpin-docs.pages.dev/" \
      org.opencontainers.image.documentation="https://coldpin-docs.pages.dev/" \
      org.opencontainers.image.source="https://github.com/hynko431/Coldpin-npx-Safe-Finder" \
      org.opencontainers.image.licenses="Apache-2.0"

# Git is required only for read-only tarball-to-Git parity and patient-zero commit bisection (resolve-anchor).
RUN apk add --no-cache git ca-certificates \
    && mkdir -p /app /tmp/coldpin-cache \
    && chown -R node:node /app /tmp/coldpin-cache

WORKDIR /app

# Copy strictly allowlisted zero-dependency runtime artifacts (no npm install, no build tools, no tests/secrets)
COPY --chown=node:node package.json LICENSE README.md ./
COPY --chown=node:node lib ./lib
COPY --chown=node:node catalog ./catalog

ENV NODE_ENV=production \
    NODE_OPTIONS=--no-warnings \
    COLDPIN_CACHE_DIR=/tmp/coldpin-cache

USER node

ENTRYPOINT ["node", "--no-warnings", "/app/lib/cli.mjs"]
CMD ["--help"]
