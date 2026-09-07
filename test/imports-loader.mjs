//node --experimental-loader resolver.
//the tests import the real src/wisp.js, whose imports of "./net.js" and
//"./ratelimit.js" target the cloudflare worker runtime. this hook redirects
//those module specifiers to portable in-test stubs so the protocol core can be
//exercised on plain node (cloudflare:sockets is not importable outside a worker).

import { fileURLToPath } from "node:url"

const stubMap = {
  "./net.js": "./stubs/net.js",
  "./config.js": "./stubs/config.js",
  "./ratelimit.js": "./stubs/ratelimit.js"
}

export async function resolve(specifier, context, nextResolve) {
  if (context.parentURL) {
    const parent = fileURLToPath(context.parentURL)
    if (parent.endsWith("/src/wisp.js") && specifier in stubMap) {
      const target = new URL(stubMap[specifier], import.meta.url)
      return nextResolve(target.href, context)
    }
  }
  return nextResolve(specifier, context)
}