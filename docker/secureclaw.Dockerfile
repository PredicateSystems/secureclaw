# Dockerfile for SecureClaw (OpenClaw with security plugin)
# Based on Node.js with pnpm

# ============================================================================
# Stage 1: Build SecureClaw
# ============================================================================
FROM node:22-bookworm-slim AS builder

WORKDIR /app

# Install pnpm
RUN corepack enable && corepack prepare pnpm@10.23.0 --activate

# Copy package files
COPY package.json pnpm-lock.yaml* ./

# Install dependencies
RUN pnpm install --frozen-lockfile || pnpm install

# Copy source code
COPY . .

# Build
RUN pnpm build || true

# ============================================================================
# Stage 2: Runtime image
# ============================================================================
FROM node:22-bookworm-slim

WORKDIR /app

# Install pnpm
RUN corepack enable && corepack prepare pnpm@10.23.0 --activate

# Install curl for healthcheck
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy built application
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
COPY --from=builder /app/policies ./policies
COPY --from=builder /app/demo ./demo

# Environment variables for SecureClaw
ENV SECURECLAW_PRINCIPAL=agent:secureclaw
ENV SECURECLAW_POLICY=./policies/default.json
ENV PREDICATE_SIDECAR_URL=http://sidecar:8787
ENV SECURECLAW_FAIL_OPEN=false
ENV SECURECLAW_VERBOSE=true
ENV NODE_ENV=production

# Create non-root user
RUN useradd -m -s /bin/bash openclaw
USER openclaw

# Default port for OpenClaw gateway (if used)
EXPOSE 18789

# Default command - run the TUI
ENTRYPOINT ["node", "dist/index.js"]
CMD ["tui"]