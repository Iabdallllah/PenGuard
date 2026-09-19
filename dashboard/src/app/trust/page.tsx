import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "PenGuard Trust Center",
  description: "Data retention, sub-processors, and token-scope policy for PenGuard",
};

const API_BASE = "https://heroic-insight-production-d97d.up.railway.app";

function Card({ title, body }: { title: string; body: string }) {
  return (
    <section className="rounded-2xl border border-[#1E293B] bg-[#0B0F1A] p-5 sm:p-6">
      <h2 className="text-sm font-bold tracking-wide text-white">{title}</h2>
      <p className="mt-2 text-sm leading-relaxed text-slate-400">{body}</p>
    </section>
  );
}

export default function TrustPage() {
  return (
    <main className="min-h-screen bg-[#06080F] text-slate-200">
      <div className="mx-auto max-w-3xl px-5 py-10 sm:py-14 space-y-4">
        <header className="space-y-2">
          <p className="text-[11px] font-bold tracking-widest uppercase text-cyan-400">
            PenGuard · Trust Center
          </p>
          <h1 className="text-2xl sm:text-3xl font-black text-white">
            How PenGuard handles your security
          </h1>
          <p className="text-sm text-slate-500">
            Machine-readable disclosure:{" "}
            <a
              href={`${API_BASE}/.well-known/security.txt`}
              className="font-mono text-cyan-300 hover:text-cyan-200"
            >
              /.well-known/security.txt
            </a>{" "}
            (RFC 9116) · Full policy:{" "}
            <a
              href="https://github.com/Iabdallllah/PenGuard/blob/main/SECURITY.md"
              className="font-mono text-cyan-300 hover:text-cyan-200"
            >
              SECURITY.md
            </a>
          </p>
        </header>

        <Card
          title="1 · Data retention — zero training reuse"
          body="Customer code, exploit payloads, and episode telemetry are never used to train models. Episodes persist only as an operational audit ledger (PostgreSQL + local JSON fallback) and can be purged at any time via DELETE /api/episodes with an operator key."
        />
        <Card
          title="2 · Sub-processors"
          body="Groq (LLM inference only, no training retention) · Railway (API + target hosting, PostgreSQL) · Vercel (dashboard hosting) · GitHub (remediation pull requests and re-test verdict comments). No other third party receives customer data."
        />
        <Card
          title="3 · Least-privilege token scope"
          body="The GitHub token needs only pull-request write scope: open remediation branches, file patches, post re-test verdict comments, and approve on operator command. It cannot read unrelated private repositories, and every approval is verified against the originating episode before posting."
        />
        <Card
          title="4 · Tamper-evident reports"
          body="Compliance exports can be frozen with POST /api/reports/seal, which stores a SHA-256 snapshot. Any auditor can confirm a report byte-for-byte with GET /api/reports/verify/{hash} — no account required."
        />

        <footer className="pt-2 text-sm">
          <Link href="/" className="text-cyan-300 hover:text-cyan-200">
            ← Back to Command Center
          </Link>
        </footer>
      </div>
    </main>
  );
}
