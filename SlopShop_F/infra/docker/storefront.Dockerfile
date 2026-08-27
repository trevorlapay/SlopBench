# syntax=docker/dockerfile:1.12
#
# Storefront image.
#
# Build and runtime stages are separate. Both base images are pinned by digest.

FROM node:22.12.0-bookworm-slim@sha256:0bcbba0c74e9f8f1c9e4a4bfd45d2b71cd6a4a55c0e50e1e9d5e10c0c0a2e4d1 AS build

WORKDIR /src

ENV NODE_ENV=production \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false

# Dependencies are installed from the lockfile alone.
COPY --chown=node:node services/storefront/package.json services/storefront/package-lock.json ./
RUN npm ci --include=dev --ignore-scripts

COPY --chown=node:node services/storefront/tsconfig.json ./
COPY --chown=node:node services/storefront/src ./src

RUN npm run build \
    && npm prune --omit=dev \
    && npm cache clean --force


FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:3a2c1f0e9b8d7c6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a AS runtime

WORKDIR /app

# The distroless nonroot variant runs as uid 65532.
USER nonroot:nonroot

ENV NODE_ENV=production \
    PORT=8080 \
    NODE_OPTIONS=--max-old-space-size=384

COPY --from=build --chown=nonroot:nonroot /src/node_modules ./node_modules
COPY --from=build --chown=nonroot:nonroot /src/dist ./dist
COPY --from=build --chown=nonroot:nonroot /src/package.json ./package.json

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

# Runtime configuration arrives as environment variables projected from the
# secret store.
ENTRYPOINT ["/nodejs/bin/node", "dist/server.js"]
