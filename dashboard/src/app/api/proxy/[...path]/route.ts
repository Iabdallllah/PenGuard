import type { NextRequest } from "next/server";

// Server-side BFF: the browser never receives the backend API key.
// PENGUARD_API_KEY is a server-only variable (never NEXT_PUBLIC_*).
export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const BACKEND = (
  process.env.PENGUARD_API_BASE ||
  process.env.NEXT_PUBLIC_API_BASE ||
  "http://127.0.0.1:8000"
)
  .trim()
  .replace(/\/$/, "");

const API_KEY =
  process.env.PENGUARD_API_KEY ||
  // Development-only fallback matching the backend's non-production fallback.
  // Never shipped to the browser; production requires an explicit env var.
  (process.env.NODE_ENV !== "production" ? "dev-local-penguard-key-change-me" : "");

const ALLOWED_METHODS = new Set(["GET", "POST", "DELETE", "HEAD"]);
const UPSTREAM_TIMEOUT_MS = Number(process.env.PENGUARD_PROXY_TIMEOUT_MS || 120000);

type RouteParams = { params: Promise<{ path: string[] }> };

async function proxyRequest(request: NextRequest, context: RouteParams): Promise<Response> {
  const method = request.method.toUpperCase();
  if (!ALLOWED_METHODS.has(method)) {
    return Response.json({ detail: "Method not allowed" }, { status: 405 });
  }
  if (!API_KEY) {
    // Fail closed: never proxy without a configured server-side credential.
    return Response.json(
      { detail: "Server API credential is not configured (PENGUARD_API_KEY)." },
      { status: 503 },
    );
  }

  const { path } = await context.params;
  // The client calls /api/proxy/api/episodes, so the captured path already
  // includes the backend's /api prefix. Forward it verbatim (no double prefix).
  const target = `${BACKEND}/${path.join("/")}${request.nextUrl.search}`;

  const headers = new Headers();
  headers.set("X-API-Key", API_KEY);
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("Content-Type", contentType);

  try {
    const init: RequestInit = {
      method,
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    };
    if (method === "POST") {
      init.body = await request.arrayBuffer();
    }
    const upstream = await fetch(target, init);

    const body = await upstream.arrayBuffer();
    const responseHeaders = new Headers();
    const upstreamType = upstream.headers.get("content-type");
    if (upstreamType) responseHeaders.set("Content-Type", upstreamType);
    const disposition = upstream.headers.get("content-disposition");
    if (disposition) responseHeaders.set("Content-Disposition", disposition);
    return new Response(body, { status: upstream.status, headers: responseHeaders });
  } catch (error) {
    const detail = error instanceof Error ? error.message : "upstream request failed";
    return Response.json({ detail: `Backend unreachable: ${detail}` }, { status: 502 });
  }
}

export async function GET(request: NextRequest, context: RouteParams) {
  return proxyRequest(request, context);
}

export async function POST(request: NextRequest, context: RouteParams) {
  return proxyRequest(request, context);
}

export async function DELETE(request: NextRequest, context: RouteParams) {
  return proxyRequest(request, context);
}

export async function HEAD(request: NextRequest, context: RouteParams) {
  return proxyRequest(request, context);
}
