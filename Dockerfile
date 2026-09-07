# Run the Wisp Cloudflare Worker locally via wrangler dev (workerd).
FROM node:22-slim

ENV WRANGLER_SEND_METRICS=false

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY wrangler.toml ./
COPY src ./src
COPY assets ./assets

EXPOSE 8787
CMD ["npx", "wrangler", "dev", "--local", "--ip", "0.0.0.0", "--port", "8787"]