import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // REST traffic intentionally goes through the server-side BFF route at
  // /api/proxy/[...path], which attaches PENGUARD_API_KEY server-side.
  //
  // There is deliberately no /api/:path* rewrite: array-form rewrites run
  // before dynamic routes, so a catch-all rewrite would shadow the BFF route
  // handler. The direct WebSocket connection uses NEXT_PUBLIC_API_BASE and
  // does not pass through Next.js.
};

export default nextConfig;
