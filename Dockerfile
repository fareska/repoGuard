FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/shared/package.json packages/shared/package.json
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm --filter @repoguard/web build

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8787
ENV HOST=0.0.0.0
ENV SCAN_MODE=mock
ENV ALLOW_MOCK_MODE=true
ENV DATABASE_URL=/data/repoguard.sqlite
ENV WEB_DIST=/app/apps/web/dist
ENV NODE_OPTIONS=--max-old-space-size=512
RUN corepack enable && mkdir -p /data && chown -R node:node /data
COPY --from=build --chown=node:node /app /app
USER node
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD node -e "fetch('http://127.0.0.1:8787/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["./node_modules/.bin/tsx", "apps/api/src/main.ts"]
