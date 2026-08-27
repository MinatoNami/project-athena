FROM node:22-alpine AS build
WORKDIR /app
# `npm ci` from a committed lockfile: reproducible, and it skips the resolver entirely
# (npm 10, which ships with node 22, mis-resolves this dependency graph).
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
# Baked, not set at runtime: Nuxt writes asset URLs into the client manifest during
# the build, so an app mounted at /athena/ with a runtime-only base still asks for
# /_nuxt/... and every asset 404s.
ARG NUXT_APP_BASE_URL=/
ENV NUXT_APP_BASE_URL=${NUXT_APP_BASE_URL}
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/.output ./.output
USER node
ARG NUXT_APP_BASE_URL=/
ENV NITRO_PORT=3000 NITRO_HOST=0.0.0.0 NODE_ENV=production NUXT_APP_BASE_URL=${NUXT_APP_BASE_URL}
EXPOSE 3000
CMD ["node", ".output/server/index.mjs"]
