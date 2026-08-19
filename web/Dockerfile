FROM node:22-alpine AS build
WORKDIR /app
# `npm ci` from a committed lockfile: reproducible, and it skips the resolver entirely
# (npm 10, which ships with node 22, mis-resolves this dependency graph).
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/.output ./.output
USER node
ENV NITRO_PORT=3000 NITRO_HOST=0.0.0.0 NODE_ENV=production
EXPOSE 3000
CMD ["node", ".output/server/index.mjs"]
