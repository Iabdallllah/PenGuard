import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Proxy /api to FastAPI control plane to avoid CORS when using relative API_BASE
  // In production Vercel, NEXT_PUBLIC_API_BASE=https://purple-api.onrender.com
  async rewrites() {
    const apiBase = process.env.NEXT_PUBLIC_API_BASE || "http://127.0.0.1:8000";
    // When deployed on Vercel with single Docker (start.sh), API and target run together; vercel.json also defines rewrite as backup
    return [
      {
        source: "/api/:path*",
        destination: `${apiBase.replace(/\/$/, "")}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
