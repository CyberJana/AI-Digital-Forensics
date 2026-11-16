FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS dependencies

WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund

FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build

WORKDIR /app
ARG NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL}
COPY --from=dependencies /app/node_modules ./node_modules
COPY frontend/ ./
RUN npm run build

FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS runtime

ENV NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0
WORKDIR /app
RUN addgroup -S -g 10001 nextjs \
    && adduser -S -u 10001 -G nextjs nextjs \
    && rm -rf /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx \
    && mkdir -p .next/cache \
    && chown -R nextjs:nextjs /app
COPY --from=build --chown=nextjs:nextjs /app/.next/standalone ./
COPY --from=build --chown=nextjs:nextjs /app/.next/static ./.next/static
USER 10001:10001
EXPOSE 3000
CMD ["node", "server.js"]
