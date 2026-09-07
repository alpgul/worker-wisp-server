#!/bin/sh
# Copy the client artifacts that assets/index.html loads (libcurl.js, libcurl.wasm)
# from the shared build volume produced by the `client` compose service, then start
# the dev server. Nothing is copied when the volume is empty, so the worker still
# starts with whatever is baked into the image.
set -eu

if [ -d /client-out ]; then
  for f in libcurl.js libcurl.wasm; do
    if [ -f "/client-out/$f" ]; then
      cp "/client-out/$f" /app/assets/
      echo "synced /client-out/$f -> assets/"
    fi
  done
fi

exec npx wrangler dev --local --ip 0.0.0.0 --port 8787