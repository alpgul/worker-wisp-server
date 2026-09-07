# Run the Wisp Cloudflare Worker locally via wrangler dev (workerd).
FROM node:22-slim

ENV WRANGLER_SEND_METRICS=false

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY wrangler.toml ./
COPY src ./src
COPY assets ./assets
COPY entrypoint.sh ./

EXPOSE 8787
CMD ["sh", "/app/entrypoint.sh"]