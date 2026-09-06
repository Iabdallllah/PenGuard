import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Proxy /api to FastAPI control plane to avoid CORS when using relative API_BASE
  // In production Vercel/Railway, NEXT_PUBLIC_API_BASE=https://purple-api.onrender.com
  async rewrites() {
    const raw = (process.env.NEXT_PUBLIC_API_BASE || "").trim();
    let apiBase = raw || "http://127.0.0.1:8000";
    // Railway may provide value without protocol (e.g. penguard-api.up.railway.app)
    if (apiBase && !apiBase.startsWith("http://") && !apiBase.startsWith("https://") && !apiBase.startsWith("/")) {
      apiBase = `https://${apiBase}`;
    }
    // Ensure valid destination (must start with / or http)
    if (!apiBase.startsWith("/") && !apiBase.startsWith("http")) {
      apiBase = "http://127.0.0.1:8000";
    }
    return [
      {
        source: "/api/:path*",
        destination: `${apiBase.replace(/\/$/, "")}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
