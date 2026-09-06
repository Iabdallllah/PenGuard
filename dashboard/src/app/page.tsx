"use client";

import React, { useState, useEffect, useMemo, useRef } from "react";

// ─────────────────────────────────────────────────────────────
// BRAND: PENGUARD — Security Operations Center
// Project renamed from VANGUARD → PENGUARD (capital as before)
// ─────────────────────────────────────────────────────────────
const BRAND = {
  name: "PENGUARD",
  wordmark: "PENGUARD",
  tagline: "Security Operations Center",
  descriptor: "Continuous Security Operations",
  reportFilename: "penguard-audit-report.pdf",
};

// Integration: use relative proxy via Next rewrites by default to avoid CORS (localhost vs 127.0.0.1)
// Set NEXT_PUBLIC_API_BASE=http://127.0.0.1:8000 to force absolute; empty → "/api/..."
const ENV_API_BASE = (typeof process !== "undefined" && (process.env.NEXT_PUBLIC_API_BASE as string)) || "";
const API_BASE = ENV_API_BASE.replace(/\/$/, "");
function apiUrl(path: string) {
  // path should start with "/"
  if (API_BASE) return `${API_BASE}${path}`;
  return path; // relative → handled by next.config.ts rewrites → http://127.0.0.1:8000
}
const API_DISPLAY = API_BASE || "/api";

// Normalization helper: backend now returns scenario key (idor/sql_injection/business_logic/xss)
// but legacy records or raw vulnerability_target like "SQL Injection" are mapped for UI rendering
function normalizeAttackKey(raw: string): ScenarioKey | null {
  if (!raw) return null;
  const k = raw.trim().toLowerCase().replace(/\s+/g, "_").replace(/-/g, "_");
  if (k === "idor") return "idor";
  if (k === "sql_injection" || raw.toLowerCase() === "sql injection") return "sql_injection";
  if (k === "business_logic_abuse" || k === "business_logic" || raw.toLowerCase() === "business logic abuse") return "business_logic";
  if (k === "xss" || k === "cross_site_scripting" || raw.toLowerCase().includes("cross") || raw.toLowerCase() === "xss") return "xss";
  // already correct keys
  if (raw === "idor" || raw === "sql_injection" || raw === "business_logic" || raw === "xss") return raw as ScenarioKey;
  return null;
}

interface Episode {
  id: string;
  target: string;
  attack_type: string; // normalized to ScenarioKey via backend, but legacy values handled via normalizeAttackKey
  attack_label?: string;
  status: number;
  retest_status: number | null;
  patch_applied: boolean;
  threat_flag: boolean;
  score: number;
  remediation: string;
  logs?: string[];
  timestamp?: string;
  duration_ms?: number;
  scenario?: string;
  base_url?: string;
  pr_url?: string | null;
  recon_data?: any;
  detection_report?: any;
  hardening_plan?: any;
  response_body?: string;
}

type ScenarioKey = "idor" | "sql_injection" | "business_logic" | "xss";

const SCENARIOS: Record<
  ScenarioKey,
  { label: string; short: string; owasp: string; severity: "high" | "critical" | "medium"; desc: string }
> = {
  idor: {
    label: "IDOR / Broken Access Control",
    short: "IDOR",
    owasp: "A01:2021",
    severity: "high",
    desc: "Object-level authorization bypass",
  },
  sql_injection: {
    label: "SQL Injection",
    short: "SQLi",
    owasp: "A03:2021",
    severity: "critical",
    desc: "Unsanitized query exploitation",
  },
  business_logic: {
    label: "Business Logic Abuse",
    short: "Logic",
    owasp: "A04:2021",
    severity: "medium",
    desc: "Workflow & state manipulation",
  },
  xss: {
    label: "Cross-Site Scripting (XSS)",
    short: "XSS",
    owasp: "A03:2021",
    severity: "critical",
    desc: "Reflected script injection",
  },
};

// ── Inline icons (no external deps) ─────────────────────────
const Icon = {
  Shield: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <path d="M12 3l7 4v5c0 5-3.5 8.5-7 9-3.5-.5-7-4-7-9V7l7-4z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  ),
  Activity: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <path d="M3 12h4l2-6 4 12 2-6h6" />
    </svg>
  ),
  Zap: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <path d="M13 2L3 14h7l-1 8 10-12h-7l1-8z" />
    </svg>
  ),
  Layers: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <path d="M12 3l9 4.5L12 12 3 7.5 12 3z" />
      <path d="M3 12l9 4.5L21 12" />
      <path d="M3 16.5L12 21l9-4.5" />
    </svg>
  ),
  Target: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="3" />
      <path d="M12 4v2M12 18v2M4 12h2M18 12h2" />
    </svg>
  ),
  Search: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <circle cx="11" cy="11" r="7" />
      <path d="M20 20l-3.5-3.5" />
    </svg>
  ),
  Chevron: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <path d="M6 9l6 6 6-6" />
    </svg>
  ),
  External: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <path d="M14 3h7v7" />
      <path d="M10 14L21 3" />
      <path d="M21 14v7H3V3h7" />
    </svg>
  ),
  Clock: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </svg>
  ),
  Terminal: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <path d="M4 17l5-5-5-5" />
      <path d="M12 17h6" />
      <rect x="2" y="3" width="20" height="18" rx="2" />
    </svg>
  ),
  Check: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" {...p}>
      <path d="M5 13l4 4L19 7" />
    </svg>
  ),
  Alert: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <path d="M12 3l9 16H3L12 3z" />
      <path d="M12 9v5M12 16h.01" />
    </svg>
  ),
  Menu: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <path d="M4 6h16M4 12h16M4 18h16" />
    </svg>
  ),
  X: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <path d="M6 6l12 12M18 6L6 18" />
    </svg>
  ),
  PanelExpand: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M9 3v18" />
      <path d="M13 9l3 3-3 3" />
    </svg>
  ),
  PanelCollapse: (p: any) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}>
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M9 3v18" />
      <path d="M16 15l-3-3 3-3" />
    </svg>
  ),
};

function cn(...c: (string | false | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

// ── Custom Dropdown (Tailwind / shadcn-style, Radix-inspired) ──
// Design: surface #0E1626, border #1E293B, muted white text, electric cyan highlight
// Motion: fade-in + scale-95 -> scale-100 with transition-all
// A11y: ARIA combobox/listbox/option, keyboard nav, outside close
function ScenarioSelect({
  value,
  onValueChange,
}: {
  value: ScenarioKey;
  onValueChange: (v: ScenarioKey) => void;
}) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) setOpen(false);
    };
    if (open) document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  // close on escape & keyboard nav
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!open) return;
      if (e.key === "Escape") {
        setOpen(false);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  const options = Object.entries(SCENARIOS) as [ScenarioKey, typeof SCENARIOS[ScenarioKey]][];

  return (
    <div ref={containerRef} className="relative w-full">
      <button
        type="button"
        role="combobox"
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-controls="scenario-listbox"
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "w-full flex items-center justify-between gap-2 pl-3 pr-3 py-2.5 rounded-xl bg-[#0E1626] border text-sm text-slate-200 transition-all outline-none",
          open ? "border-cyan-500/50 ring-4 ring-cyan-500/10" : "border-[#1E293B] hover:border-[#334155] focus:border-cyan-500/40 focus:ring-4 focus:ring-cyan-500/10"
        )}
      >
        <span className="truncate text-left flex items-center gap-2">
          <span className="hidden sm:inline-flex items-center justify-center w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-[0_0_6px_rgba(34,211,238,0.8)]" />
          <span className="mono text-xs sm:text-sm">
            {SCENARIOS[value].owasp} · {SCENARIOS[value].label}
          </span>
        </span>
        <Icon.Chevron
          className={cn("w-4 h-4 text-slate-500 shrink-0 transition-transform duration-200", open && "rotate-180 text-cyan-400")}
        />
      </button>

      {/* Dropdown panel */}
      <div
        id="scenario-listbox"
        ref={listRef}
        role="listbox"
        aria-label="Scenario"
        className={cn(
          "absolute z-50 mt-2 w-full rounded-xl border border-[#1E293B] bg-[#0E1626] shadow-2xl shadow-black/60 overflow-hidden origin-top transition-all duration-150 ease-out",
          open ? "opacity-100 scale-100 translate-y-0" : "opacity-0 scale-95 -translate-y-1 pointer-events-none"
        )}
      >
        <div className="p-1.5 max-h-[280px] overflow-auto custom-scrollbar">
          {options.map(([key, scen]) => {
            const isSelected = value === key;
            return (
              <button
                key={key}
                role="option"
                aria-selected={isSelected}
                onClick={() => {
                  onValueChange(key);
                  setOpen(false);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    onValueChange(key);
                    setOpen(false);
                  }
                }}
                className={cn(
                  "w-full text-left flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors",
                  isSelected
                    ? "bg-cyan-500/10 border border-cyan-500/20 text-cyan-300"
                    : "text-slate-300 hover:bg-[#1E293B] hover:text-white border border-transparent"
                )}
              >
                <span className="flex-1 min-w-0">
                  <span className="flex items-center gap-2">
                    <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", scen.severity === "critical" ? "bg-rose-400" : scen.severity === "high" ? "bg-amber-400" : "bg-cyan-400")} />
                    <span className="font-semibold mono text-xs">{scen.owasp}</span>
                    <span className="text-[11px] px-1.5 py-0.5 rounded bg-[#1E293B] border border-[#334155] text-slate-400 mono hidden sm:inline">{scen.short}</span>
                  </span>
                  <span className="block text-xs font-medium mt-0.5 truncate">{scen.label}</span>
                  <span className="block text-[11px] text-slate-500 truncate">{scen.desc}</span>
                </span>
                {isSelected && <Icon.Check className="w-4 h-4 text-cyan-400 shrink-0" />}
              </button>
            );
          })}
        </div>
        <div className="px-3 py-2 border-t border-[#1E293B] bg-[#0B1220] flex items-center justify-between">
          <span className="text-[11px] text-slate-500 mono">OWASP Top 10</span>
          <span className="text-[11px] text-cyan-400 mono font-bold">3 vectors</span>
        </div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [episodes, setEpisodes] = useState<Episode[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<ScenarioKey>("idor");
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:8001");
  const [isDispatching, setIsDispatching] = useState(false);
  const [activeInspector, setActiveInspector] = useState<Episode | null>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "patched" | "threat">("all");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [showLogs, setShowLogs] = useState(true);
  const [dispatchError, setDispatchError] = useState<string | null>(null);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [activeNav, setActiveNav] = useState("Command Center");
  const [navToast, setNavToast] = useState<string | null>(null);
  const [heartbeat, setHeartbeat] = useState<string>("--:--:--");
  useEffect(() => {
    const tick = () => setHeartbeat(new Date().toLocaleTimeString());
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const handleNavClick = (label: string) => {
    setActiveNav(label);
    // Smooth scroll without changing visual layout — keep shape identical
    const map: Record<string, string> = {
      "Command Center": "top",
      "Attack Ledger": "audit-history",
      "Agent Fleet": "metrics-section",
      "Findings": "audit-history",
      "Compliance Reports": "audit-history",
      "Integrations": "top",
      "Settings": "top",
    };
    const targetId = map[label] || "top";
    if (label === "Findings") setStatusFilter("threat");
    else if (label === "Attack Ledger") setStatusFilter("all");
    if (targetId === "top") {
      window.scrollTo({ top: 0, behavior: "smooth" });
    } else {
      document.getElementById(targetId)?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    // Governancesecondary show toast for unimplemented
    if (["Integrations", "Settings", "Agent Fleet"].includes(label)) {
      setNavToast(`${label} — قريباً`);
      setTimeout(() => setNavToast(null), 2200);
    } else if (label === "Compliance Reports") {
      downloadReport();
    }
  };

  const fetchEpisodes = async () => {
    try {
      // Try relative via proxy first, then absolute fallback (handles CORS/host mismatch)
      let res: Response | null = null;
      let lastErr: any = null;
      const urls = [apiUrl("/api/episodes"), "http://127.0.0.1:8000/api/episodes", "http://localhost:8000/api/episodes"];
      // deduplicate
      const uniq = Array.from(new Set(urls));
      for (const u of uniq) {
        try {
          const r = await fetch(u, { cache: "no-store" } as RequestInit);
          // if 404 from chromadb container interfering, try next
          if (r.ok || r.status !== 404) {
            res = r;
            break;
          }
        } catch (e) {
          lastErr = e;
        }
      }
      if (!res) throw lastErr || new Error("fetch failed");
      if (res.ok) {
        const data = await res.json();
        setEpisodes(data);
        setFetchError(null);
        if (data.length > 0 && !activeInspector) {
          setActiveInspector(data[data.length - 1]);
        }
      } else {
        setFetchError(`API ${res.status}`);
      }
    } catch (err) {
      setFetchError("Agent fleet unreachable");
      console.error("Failed to fetch episodes:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchEpisodes();
    // Real-time via WebSocket with polling fallback
    let ws: WebSocket | null = null;
    let pollId: any = setInterval(fetchEpisodes, 5000);
    let wsAlive = false;

    const getWsUrl = () => {
      try {
        if (API_BASE) {
          return `${API_BASE.replace(/^http/, "ws")}/ws/episodes`;
        }
        // For Vercel production, NEXT_PUBLIC_API_BASE is https://heroic-insight...
        // For local relative proxy, fallback to direct 8000
        if (typeof window !== "undefined" && window.location.hostname !== "localhost" && window.location.hostname !== "127.0.0.1") {
          // On Vercel, try to derive from page origin is vercel.app, not api, so use direct api fallback
          return "wss://heroic-insight-production-d97d.up.railway.app/ws/episodes";
        }
        return "ws://127.0.0.1:8000/ws/episodes";
      } catch {
        return "ws://127.0.0.1:8000/ws/episodes";
      }
    };

    const connectWs = () => {
      try {
        const url = getWsUrl();
        ws = new WebSocket(url);
        ws.onopen = () => {
          wsAlive = true;
        };
        ws.onmessage = (ev) => {
          try {
            const data = JSON.parse(ev.data);
            if (Array.isArray(data)) {
              setEpisodes(data);
              setFetchError(null);
              setIsLoading(false);
              // keep activeInspector if null
              if (data.length > 0) {
                setActiveInspector((prev: Episode | null) => prev || data[data.length - 1]);
              }
              // stop polling when WS is alive
              if (pollId) {
                clearInterval(pollId);
                pollId = null;
              }
            }
          } catch {}
        };
        ws.onclose = () => {
          wsAlive = false;
          if (!pollId) pollId = setInterval(fetchEpisodes, 5000);
          setTimeout(connectWs, 5000);
        };
        ws.onerror = () => {
          try {
            ws?.close();
          } catch {}
        };
      } catch {
        if (!pollId) pollId = setInterval(fetchEpisodes, 5000);
      }
    };

    connectWs();

    return () => {
      try {
        ws?.close();
      } catch {}
      if (pollId) clearInterval(pollId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const dispatchScenario = async () => {
    setIsDispatching(true);
    setDispatchError(null);
    // Allow empty (means isolated sandbox) or valid URL; default sandbox URL is treated as empty for backend sandbox lifecycle
    const trimmed = targetUrl.trim();
    if (trimmed !== "") {
      try {
        new URL(trimmed);
      } catch {
        setDispatchError("Invalid target URL");
        setIsDispatching(false);
        return;
      }
    }
    try {
      const res = await fetch(apiUrl("/api/episodes/run"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario: selectedScenario,
          // Backend now understands default sandbox URL as isolated request; sending as-is keeps UI shape unchanged
          target_url: trimmed,
        }),
      });
      if (res.ok) {
        const responseData = await res.json();
        await fetchEpisodes();
        if (responseData.episode) {
          setActiveInspector(responseData.episode);
        } else if (responseData.id) {
          setActiveInspector(responseData);
        }
      } else {
        const t = await res.text();
        setDispatchError(t || `Dispatch failed (${res.status})`);
      }
    } catch (err) {
      setDispatchError("Failed to reach control plane");
      console.error("Failed to dispatch episode:", err);
    } finally {
      setIsDispatching(false);
    }
  };

  const downloadReport = () => {
    const link = document.createElement("a");
    link.href = apiUrl("/api/reports/compliance");
    link.download = BRAND.reportFilename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // derived
  const completedLoops = episodes.length;
  const appliedPatches = episodes.filter((e) => e.patch_applied).length;
  const activeThreats = episodes.filter((e) => e.threat_flag && !e.patch_applied).length;
  const mitigatedThreats = episodes.filter((e) => e.threat_flag && e.patch_applied).length;
  const postureScore =
    completedLoops > 0
      ? Math.round(episodes.reduce((acc, curr) => acc + (curr.score || 0), 0) / completedLoops)
      : 100;
  const postureGrade = postureScore >= 90 ? "A" : postureScore >= 75 ? "B" : postureScore >= 60 ? "C" : postureScore >= 40 ? "D" : "F";
  const postureColor =
    postureScore >= 80 ? "text-emerald-400" : postureScore >= 60 ? "text-amber-400" : "text-rose-400";
  const postureRing = postureScore >= 80 ? "#10b981" : postureScore >= 60 ? "#f59e0b" : "#f43f5e";

  const filteredEpisodes = useMemo(() => {
    let list = [...episodes].reverse();
    if (statusFilter === "patched") list = list.filter((e) => e.patch_applied);
    if (statusFilter === "threat") list = list.filter((e) => e.threat_flag);
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (e) =>
          e.id.toLowerCase().includes(q) ||
          e.attack_type.toLowerCase().includes(q) ||
          e.target.toLowerCase().includes(q) ||
          e.remediation.toLowerCase().includes(q)
      );
    }
    return list;
  }, [episodes, searchQuery, statusFilter]);

  const trendPoints = useMemo(() => {
    if (episodes.length === 0) return [];
    return episodes.map((e) => e.score);
  }, [episodes]);

  const chart = useMemo(() => {
    const w = 800;
    const h = 160;
    const pad = 16;
    const pts = trendPoints;
    if (pts.length === 0) return null;
    if (pts.length === 1) {
      const y = h - pad - (pts[0] / 100) * (h - pad * 2);
      return { w, h, path: `M ${pad} ${y} L ${w - pad} ${y}`, area: "", dots: [{ x: w / 2, y }] };
    }
    const stepX = (w - pad * 2) / (pts.length - 1);
    const yOf = (v: number) => h - pad - (v / 100) * (h - pad * 2);
    let d = "";
    const dots: { x: number; y: number; v: number }[] = [];
    pts.forEach((v, i) => {
      const x = pad + i * stepX;
      const y = yOf(v);
      dots.push({ x, y, v });
      d += i === 0 ? `M ${x} ${y}` : ` L ${x} ${y}`;
    });
    const smooth = d;
    const area = `${smooth} L ${pad + (pts.length - 1) * stepX} ${h - pad} L ${pad} ${h - pad} Z`;
    return { w, h, path: smooth, area, dots, stepX, yOf };
  }, [trendPoints]);

  return (
    <div className="min-h-screen bg-[#06080F] text-slate-300 selection:bg-violet-500/30 selection:text-white">
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap');
      *{font-family:Inter,system-ui,sans-serif}
      .mono{font-family:'JetBrains Mono',monospace}
      /* ── Custom Modern Dark Scrollbar ──
         thin 4px (~w-1.5), transparent track, thumb #1E293B -> hover #334155, pill ends */
      * {
        scrollbar-width: thin;
        scrollbar-color: #1E293B transparent;
      }
      *::-webkit-scrollbar {
        width: 6px;
        height: 6px;
      }
      *::-webkit-scrollbar-track {
        background: transparent;
      }
      *::-webkit-scrollbar-thumb {
        background-color: #1E293B;
        border-radius: 9999px;
        border: 1px solid transparent;
        background-clip: content-box;
      }
      *::-webkit-scrollbar-thumb:hover {
        background-color: #334155;
      }
      *::-webkit-scrollbar-corner {
        background: transparent;
      }
      .custom-scrollbar {
        scrollbar-width: thin;
        scrollbar-color: #1E293B transparent;
      }
      .custom-scrollbar::-webkit-scrollbar {
        width: 6px;
        height: 6px;
      }
      .custom-scrollbar::-webkit-scrollbar-thumb {
        background-color: #1E293B;
        border-radius: 9999px;
      }
      .custom-scrollbar::-webkit-scrollbar-thumb:hover {
        background-color: #334155;
      }
      /* high contrast focus */
      :focus-visible {
        outline: 2px solid #22d3ee;
        outline-offset: 2px;
      }
      `}</style>

      <div
        className="pointer-events-none fixed inset-0 opacity-[0.035]"
        style={{
          backgroundImage:
            "linear-gradient(to right, #fff 1px, transparent 1px), linear-gradient(to bottom, #fff 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      <div className="flex min-h-screen">
        {/* ─── Sidebar — Collapsible Rail Mode ─── */}
        <aside
          aria-label="Primary"
          className={cn(
            "hidden lg:flex shrink-0 flex-col border-r border-slate-800/80 bg-[#0B0F1A]/80 backdrop-blur-xl sticky top-0 h-screen transition-all duration-300 ease-in-out",
            isCollapsed ? "w-20" : "w-[288px]",
            "max-lg:fixed max-lg:inset-y-0 max-lg:left-0 max-lg:z-50 max-lg:w-[300px] max-lg:transition-transform",
            !mobileNavOpen && "max-lg:hidden"
          )}
        >
          {/* Brand — no logos, typographic only */}
          <div className={cn("border-b border-slate-800/80", isCollapsed ? "px-3 pt-6 pb-5" : "px-6 pt-6 pb-6")}>
            <div className={cn("flex items-center", isCollapsed ? "justify-center" : "justify-between gap-3")}>
              {!isCollapsed ? (
                <>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-baseline gap-2">
                      <span className="text-[16px] font-black tracking-[0.16em] text-white">{BRAND.wordmark}</span>
                      <span className="text-[10px] font-bold tracking-widest text-slate-500 border border-slate-800 rounded px-1.5 py-0.5">
                        v2.4
                      </span>
                    </div>
                    <div className="text-[11px] font-medium tracking-wide text-slate-400 leading-none mt-1">
                      {BRAND.tagline}
                    </div>
                  </div>
                  <button
                    onClick={() => setIsCollapsed(true)}
                    aria-label="Collapse sidebar"
                    title="Collapse"
                    className="w-8 h-8 grid place-items-center rounded-lg border border-[#1E293B] bg-[#0E1626] text-slate-400 hover:text-white hover:border-[#334155] transition-colors"
                  >
                    <Icon.PanelCollapse className="w-4 h-4" />
                  </button>
                </>
              ) : (
                <button
                  onClick={() => setIsCollapsed(false)}
                  aria-label="Expand sidebar"
                  title="Expand"
                  className="w-9 h-9 grid place-items-center rounded-xl border border-[#1E293B] bg-[#0E1626] text-slate-400 hover:text-cyan-300 hover:border-cyan-500/30 transition-colors"
                >
                  <Icon.PanelExpand className="w-4 h-4" />
                </button>
              )}
            </div>

            {!isCollapsed && (
              <div className="mt-4 flex items-center gap-2 text-[11px]">
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-semibold">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
                  Live Operations
                </span>
                <span className="text-slate-600 mono text-[11px]">{completedLoops} loops</span>
              </div>
            )}
            {isCollapsed && (
              <div className="mt-4 flex justify-center">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]" title="Live" />
              </div>
            )}
          </div>

          <nav className={cn("flex-1 py-5 space-y-6 overflow-y-auto custom-scrollbar", isCollapsed ? "px-2" : "px-3")}>
            <div>
              {!isCollapsed && (
                <div className="px-3 mb-2 text-[10px] font-bold tracking-[0.14em] text-slate-500 uppercase">Operations</div>
              )}
              <div className="space-y-1">
                {[
                  { label: "Command Center", icon: Icon.Shield, desc: "Live posture & fleet" },
                  { label: "Attack Ledger", icon: Icon.Activity, desc: "All episodes" },
                  { label: "Findings", icon: Icon.Alert, badge: activeThreats ? `${activeThreats}` : undefined },
                ].map((item) => {
                  const ItemIcon = item.icon;
                  const isActive = activeNav === item.label;
                  // Collapsed: icon centered + tooltip — now interactive
                  if (isCollapsed) {
                    return (
                      <div key={item.label} className="relative group flex justify-center">
                        <button
                          type="button"
                          aria-label={item.label}
                          onClick={() => handleNavClick(item.label)}
                          className={cn(
                            "w-11 h-11 grid place-items-center rounded-xl border transition-colors cursor-pointer",
                            isActive
                              ? "bg-white text-black border-white shadow"
                              : "bg-transparent text-slate-500 border-transparent hover:bg-[#0E1626] hover:text-slate-200 hover:border-[#1E293B]"
                          )}
                        >
                          <ItemIcon className={cn("w-5 h-5 shrink-0", isActive ? "text-black" : "text-slate-500 group-hover:text-slate-300")} />
                        </button>
                        {/* tooltip */}
                        <div className="pointer-events-none absolute left-[calc(100%+10px)] top-1/2 -translate-y-1/2 opacity-0 scale-95 group-hover:opacity-100 group-hover:scale-100 transition-all duration-150 z-50">
                          <div className="whitespace-nowrap px-3 py-2 rounded-lg bg-[#0E1626] border border-[#1E293B] shadow-xl text-xs font-semibold text-slate-200">
                            {item.label}
                            {item.badge ? <span className="ml-2 mono text-[11px] px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">{item.badge}</span> : null}
                            <div className="text-[11px] font-normal text-slate-500">{item.desc ?? ""}</div>
                          </div>
                        </div>
                      </div>
                    );
                  }
                  return (
                    <button
                      type="button"
                      key={item.label}
                      onClick={() => handleNavClick(item.label)}
                      className={cn(
                        "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg border text-sm transition-colors cursor-pointer text-left",
                        isActive
                          ? "bg-white text-black border-white shadow"
                          : "bg-transparent text-slate-400 border-transparent hover:bg-slate-900 hover:text-slate-200 hover:border-slate-800"
                      )}
                    >
                      <ItemIcon className={cn("w-4 h-4 shrink-0", isActive ? "text-black" : "text-slate-500")} />
                      <div className="flex-1 min-w-0 text-left">
                        <div className={cn("text-[13px] font-semibold leading-none", isActive ? "text-black" : "text-slate-200")}>
                          {item.label}
                        </div>
                        <div className={cn("text-[11px] leading-none mt-1", isActive ? "text-zinc-600" : "text-slate-500")}>
                          {item.desc}
                        </div>
                      </div>
                      {item.badge && (
                        <span
                          className={cn(
                            "text-[10px] font-bold px-1.5 py-0.5 rounded border mono",
                            isActive
                              ? "bg-black text-white border-black"
                              : item.label === "Findings" && activeThreats
                              ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
                              : "bg-slate-900 text-slate-400 border-slate-800"
                          )}
                        >
                          {item.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* System health — hidden in rail mode or compact */}
            {!isCollapsed ? (
              <div className="mx-3 rounded-xl border border-slate-800 bg-[#0F1420] p-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-[11px] font-bold tracking-widest uppercase text-slate-400">System Health</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.8)] animate-pulse" />
                </div>
                <div className="space-y-3">
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-500">Control Plane</span>
                    <span className="text-emerald-400 font-semibold mono">Operational</span>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-500">Sandbox Fleet</span>
                    <span className="text-emerald-400 font-semibold mono">3/3 Ready</span>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-500">Mitigation Engine</span>
                    <span className="text-emerald-400 font-semibold mono">Armed</span>
                  </div>
                  <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                    <div className="h-full w-[92%] bg-gradient-to-r from-emerald-500 to-cyan-400 rounded-full" />
                  </div>
                  <div className="text-[10px] text-slate-500 mono">Uptime 99.92% · 14d</div>
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2 pt-2 border-t border-slate-800/60 mx-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse" title="System Healthy" />
                <span className="text-[10px] mono text-slate-600">92%</span>
              </div>
            )}
          </nav>

          <div className={cn("border-t border-slate-800/80", isCollapsed ? "p-3 flex justify-center" : "p-4")}>
            {isCollapsed ? (
              <div className="relative group">
                <img
                  src="https://i.pravatar.cc/100?img=12"
                  alt="operator"
                  className="w-9 h-9 rounded-full border border-slate-700"
                />
                <div className="pointer-events-none absolute left-[calc(100%+12px)] top-1/2 -translate-y-1/2 opacity-0 scale-95 group-hover:opacity-100 group-hover:scale-100 transition-all duration-150 z-50">
                  <div className="px-3 py-2 rounded-lg bg-[#0E1626] border border-[#1E293B] shadow-xl">
                    <div className="text-xs font-semibold text-white">Operator</div>
                    <div className="text-[11px] mono text-slate-500">secops@vanguard.run</div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-3">
                <img
                  src="https://i.pravatar.cc/100?img=12"
                  alt="operator"
                  className="w-8 h-8 rounded-full border border-slate-700"
                />
                <div className="flex-1 min-w-0">
                  <div className="text-[13px] font-semibold text-white leading-none">Operator</div>
                  <div className="text-[11px] text-slate-500 leading-none mt-1 mono">secops@vanguard.run</div>
                </div>
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
              </div>
            )}
          </div>
        </aside>

        {mobileNavOpen && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 lg:hidden" onClick={() => setMobileNavOpen(false)} />
        )}

        {/* ─── Main ─── */}
        <div className="flex-1 min-w-0 flex flex-col">
          <header className="sticky top-0 z-30 backdrop-blur-xl bg-[#06080F]/80 border-b border-slate-800/80">
            <div className="flex items-center gap-3 px-4 lg:px-8 py-3">
              <button
                onClick={() => setMobileNavOpen((v) => !v)}
                className="lg:hidden w-9 h-9 grid place-items-center rounded-lg border border-slate-800 bg-slate-900 text-slate-300"
                aria-label="Toggle navigation"
              >
                {mobileNavOpen ? <Icon.X className="w-4 h-4" /> : <Icon.Menu className="w-4 h-4" />}
              </button>

              {/* Desktop collapse toggle when sidebar rail not visible? Keep breadcrumb */}
              <button
                onClick={() => setIsCollapsed((v) => !v)}
                className="hidden lg:grid place-items-center w-8 h-8 rounded-lg border border-[#1E293B] bg-[#0E1626] text-slate-400 hover:text-cyan-300 hover:border-cyan-500/30 transition-colors"
                aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
                title={isCollapsed ? "Expand" : "Collapse"}
              >
                {isCollapsed ? <Icon.PanelExpand className="w-4 h-4" /> : <Icon.PanelCollapse className="w-4 h-4" />}
              </button>

              <div className="hidden lg:flex items-center gap-2 text-[11px] mono">
                <span className="text-slate-600">{BRAND.name}</span>
                <span className="text-slate-700">/</span>
                <span className="text-slate-300 font-semibold">Command Center</span>
                <span className="ml-2 hidden xl:inline-flex items-center gap-1.5 px-2 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  {BRAND.descriptor}
                </span>
              </div>

              <div className="flex-1" />

              <div className="hidden md:flex items-center gap-2">
                <span className="text-[11px] font-bold tracking-widest uppercase text-slate-500">Environment</span>
                <span className="mono text-xs px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-300 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                  isolated-sandbox
                </span>
              </div>

              <div className="h-6 w-px bg-slate-800 hidden md:block" />

              <button
                onClick={downloadReport}
                className="hidden sm:inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-white text-black text-xs font-bold tracking-wide hover:bg-zinc-100 transition-colors shadow"
              >
                <Icon.External className="w-3.5 h-3.5" />
                EXPORT AUDIT TRAIL
              </button>

              <div className="w-9 h-9 rounded-full bg-[#1E293B] border border-slate-700 grid place-items-center text-slate-300 font-bold text-xs">OP</div>
            </div>

            {fetchError && (
              <div className="mx-4 lg:mx-8 mb-3 flex items-center gap-2 px-3 py-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs">
                <Icon.Alert className="w-4 h-4 shrink-0" />
                <span className="font-medium">Control plane: {fetchError}</span>
                <span className="text-rose-400/70 hidden sm:inline">— retrying every 5s · {API_DISPLAY}/api/episodes</span>
                <button
                  onClick={fetchEpisodes}
                  className="ml-auto px-2.5 py-1 rounded-md bg-rose-500 text-white text-[11px] font-bold hover:bg-rose-600"
                >
                  Retry
                </button>
              </div>
            )}
          </header>

          <main className="px-4 lg:px-8 py-6 lg:py-8 space-y-6 max-w-[1440px] mx-auto w-full custom-scrollbar">
            <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-[22px] lg:text-[26px] font-black tracking-tight text-white leading-none">
                    Command Center
                  </h1>
                  <span className="hidden sm:inline-flex items-center gap-1.5 text-[11px] font-bold tracking-widest uppercase px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    Live
                  </span>
                </div>
                <p className="text-[13px] text-slate-400 mt-1 max-w-2xl">
                  Autonomous red-team agents probe, exploit, and harden in a closed loop. Every run is executed in an isolated
                  sandbox with automatic re-test verification.
                </p>
                <div className="flex flex-wrap items-center gap-2 mt-3 text-[11px] mono">
                  <span className="px-2 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400">
                    Fleet: <b className="text-slate-200">3 agents</b> · Idle 2 · Active 1
                  </span>
                  <span className="px-2 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400">
                    Window: <b className="text-slate-200">last 24h</b>
                  </span>
                  <span className="hidden sm:inline-flex items-center gap-1.5 px-2 py-1 rounded-full bg-violet-500/10 border border-violet-500/20 text-violet-300">
                    <Icon.Zap className="w-3 h-3" />
                    Zero-touch remediation armed
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <div className="hidden sm:flex items-center gap-2 px-3 py-2 rounded-xl bg-[#0F1420] border border-slate-800">
                  <span className="text-[11px] font-bold tracking-widest uppercase text-slate-500">Next audit in</span>
                  <span className="mono text-sm font-bold text-white">04:22:18</span>
                  <span className="w-px h-4 bg-slate-800 mx-1" />
                  <span className="text-[11px] text-slate-500 mono">UTC</span>
                </div>
                <button
                  onClick={downloadReport}
                  className="sm:hidden inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-white text-black text-xs font-bold"
                >
                  Export
                </button>
              </div>
            </div>

            {/* Command Bar — Dispatch — overflow-visible to prevent dropdown clipping */}
            <section className="rounded-2xl border border-slate-800 bg-[#0F1420] shadow-[0_10px_40px_rgba(0,0,0,0.4)] overflow-visible">
              <div className="px-5 sm:px-6 py-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 bg-gradient-to-r from-violet-500/[0.06] via-transparent to-cyan-500/[0.05]">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl bg-[#0E1626] border border-[#1E293B] grid place-items-center text-cyan-300">
                    <Icon.Zap className="w-4 h-4" />
                  </div>
                  <div>
                    <h2 className="text-sm font-bold tracking-wide text-white">Dispatch Simulation</h2>
                    <p className="text-xs text-slate-500">Launch a controlled exploit against the sandbox target. No production impact.</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 text-[11px] mono">
                  <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    Sandbox isolated
                  </span>
                  <span className="px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-300 font-semibold">
                    Read-only re-test
                  </span>
                </div>
              </div>

              <div className="p-5 sm:p-6 grid grid-cols-1 lg:grid-cols-[1.4fr_0.9fr_auto] gap-4 items-end">
                <label className="space-y-1.5">
                  <span className="text-[11px] font-bold tracking-widest uppercase text-slate-500">Target URL</span>
                  <div className="relative">
                    <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">
                      <Icon.Target className="w-4 h-4" />
                    </span>
                    <input
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="http://127.0.0.1:8001"
                      className="w-full pl-9 pr-3 py-2.5 rounded-xl bg-[#0E1626] border border-[#1E293B] focus:border-cyan-500/50 focus:ring-4 focus:ring-cyan-500/10 outline-none mono text-sm text-slate-200 placeholder:text-slate-600 transition-all"
                    />
                  </div>
                  <span className="text-[11px] text-slate-500 mono hidden sm:block" suppressHydrationWarning>
                    Must be reachable from control plane · {API_DISPLAY}
                  </span>
                </label>

                <div className="space-y-1.5">
                  <span className="text-[11px] font-bold tracking-widest uppercase text-slate-500">Scenario</span>
                  {/* Custom Dropdown — replaces native select */}
                  <ScenarioSelect value={selectedScenario} onValueChange={setSelectedScenario} />
                  <span className="text-[11px] text-slate-500 hidden sm:block">{SCENARIOS[selectedScenario].desc}</span>
                </div>

                <div className="space-y-1.5">
                  <span className="hidden lg:block text-[11px] font-bold tracking-widest uppercase text-transparent select-none">
                    Action
                  </span>
                  <button
                    onClick={dispatchScenario}
                    disabled={isDispatching}
                    className="w-full lg:w-auto inline-flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl bg-white text-black text-sm font-black tracking-wide hover:bg-zinc-100 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-black/20 transition-all active:scale-[0.98]"
                  >
                    {isDispatching ? (
                      <>
                        <span className="w-4 h-4 rounded-full border-2 border-black/20 border-t-black animate-spin" />
                        DISPATCHING...
                      </>
                    ) : (
                      <>
                        <Icon.Zap className="w-4 h-4" />
                        DISPATCH SCENARIO
                      </>
                    )}
                  </button>
                </div>
              </div>

              {dispatchError && (
                <div className="mx-5 sm:mx-6 mb-5 flex items-center gap-2 px-3 py-2 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs">
                  <Icon.Alert className="w-4 h-4" />
                  {dispatchError}
                </div>
              )}

              <div className="px-5 sm:px-6 pb-4 flex flex-wrap gap-2">
                {Object.entries(SCENARIOS).map(([key, s]) => (
                  <button
                    key={key}
                    onClick={() => setSelectedScenario(key as ScenarioKey)}
                    className={cn(
                      "px-3 py-1.5 rounded-full border text-xs font-semibold mono transition-colors",
                      selectedScenario === key
                        ? "bg-cyan-500 border-cyan-500 text-black shadow shadow-cyan-500/20"
                        : "bg-[#0E1626] border-[#1E293B] text-slate-400 hover:text-slate-200 hover:border-[#334155]"
                    )}
                  >
                    {s.short} · {s.owasp}
                  </button>
                ))}
                <span className="ml-auto text-[11px] text-slate-600 mono hidden sm:inline">
                  OWASP Top 10 coverage · Purple-team validated
                </span>
              </div>
            </section>

            {/* Metrics */}
            <section id="metrics-section" className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
              <div className="rounded-2xl border border-slate-800 bg-[#0F1420] p-5 flex flex-col">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="text-[11px] font-bold tracking-widest uppercase text-slate-500">Posture Score</div>
                    <div className="flex items-baseline gap-2 mt-2">
                      <span className={cn("text-[28px] font-black mono leading-none", postureColor)}>{postureScore}</span>
                      <span className="text-slate-600 mono text-sm">/100</span>
                      <span
                        className={cn(
                          "ml-1 px-1.5 py-0.5 rounded text-[10px] font-black mono border",
                          postureGrade === "A"
                            ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                            : postureGrade === "B"
                            ? "bg-cyan-500/10 border-cyan-500/20 text-cyan-400"
                            : postureGrade === "F" || postureGrade === "D"
                            ? "bg-rose-500/10 border-rose-500/20 text-rose-400"
                            : "bg-amber-500/10 border-amber-500/20 text-amber-400"
                        )}
                      >
                        GRADE {postureGrade}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1">Post-remediation assessment</div>
                  </div>
                  <div className="relative w-[64px] h-[64px] shrink-0">
                    <svg viewBox="0 0 64 64" className="w-full h-full -rotate-90">
                      <circle cx="32" cy="32" r="26" fill="none" stroke="#1e293b" strokeWidth="6" />
                      <circle
                        cx="32"
                        cy="32"
                        r="26"
                        fill="none"
                        stroke={postureRing}
                        strokeWidth="6"
                        strokeLinecap="round"
                        strokeDasharray={`${(postureScore / 100) * 163.36} 163.36`}
                        className="transition-all duration-700"
                      />
                    </svg>
                    <span className="absolute inset-0 grid place-items-center mono text-[11px] font-bold text-white">
                      {postureScore}%
                    </span>
                  </div>
                </div>
                <div className="mt-4 flex items-center gap-2 text-[11px] mono">
                  <span
                    className={cn(
                      "px-2 py-1 rounded-full border font-semibold",
                      activeThreats
                        ? "bg-rose-500/10 border-rose-500/20 text-rose-300"
                        : "bg-emerald-500/10 border-emerald-500/20 text-emerald-300"
                    )}
                  >
                    {activeThreats ? `${activeThreats} open threats` : "No open criticals"}
                  </span>
                  <span className="text-slate-600 hidden sm:inline">· updated now</span>
                </div>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-[#0F1420] p-5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold tracking-widest uppercase text-slate-500">Completed Loops</span>
                  <Icon.Activity className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="text-[28px] font-black mono text-white leading-none mt-3">{isLoading ? "—" : completedLoops}</div>
                <div className="text-[11px] text-slate-500 mt-1">Total closed-loop runs</div>
                <div className="mt-4 h-[32px] flex items-end gap-1">
                  {(trendPoints.length ? trendPoints.slice(-12) : [40, 55, 42, 70, 65, 80, 78]).map((v, i) => (
                    <div
                      key={i}
                      className="flex-1 rounded-t bg-gradient-to-t from-cyan-600/30 to-cyan-400/80 min-w-[6px]"
                      style={{ height: `${Math.max(12, (v / 100) * 32)}px`, opacity: 0.6 + i * 0.03 }}
                    />
                  ))}
                </div>
                <div className="text-[11px] mono text-slate-600 mt-2">
                  {appliedPatches} patches · {mitigatedThreats} mitigated
                </div>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-[#0F1420] p-5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold tracking-widest uppercase text-slate-500">Auto-Patches Applied</span>
                  <Icon.Shield className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="text-[28px] font-black mono text-emerald-400 leading-none mt-3">{appliedPatches}</div>
                <div className="text-[11px] text-slate-500 mt-1">Zero-human intervention</div>
                <div className="mt-4 flex items-center gap-2">
                  <div className="flex-1 h-2 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                    <div
                      className="h-full bg-emerald-500 rounded-full transition-all duration-700"
                      style={{ width: `${completedLoops ? (appliedPatches / completedLoops) * 100 : 0}%` }}
                    />
                  </div>
                  <span className="mono text-[11px] font-bold text-emerald-400">
                    {completedLoops ? Math.round((appliedPatches / completedLoops) * 100) : 0}%
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 mono mt-1">Success rate</div>
              </div>

              <div className="rounded-2xl border border-emerald-500/20 bg-gradient-to-br from-emerald-500/[0.08] to-cyan-500/[0.06] p-5 relative overflow-hidden">
                <div className="absolute -right-6 -top-6 w-24 h-24 rounded-full bg-emerald-500/10 blur-2xl" />
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold tracking-widest uppercase text-emerald-300/80">Active Sandbox</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.8)] animate-pulse" />
                </div>
                <div className="text-[13px] font-black tracking-widest uppercase text-emerald-400 mt-3">Dynamic Hardening</div>
                <div className="text-[11px] text-slate-400 mt-1 leading-relaxed">Isolated re-test cycle armed. Network egress blocked.</div>
                <div className="mt-4 grid grid-cols-3 gap-2 text-center">
                  <div className="rounded-lg bg-[#06080F]/70 border border-emerald-500/10 p-2">
                    <div className="mono text-[11px] font-bold text-white">3</div>
                    <div className="text-[10px] uppercase font-bold tracking-wide text-slate-500">Agents</div>
                  </div>
                  <div className="rounded-lg bg-[#06080F]/70 border border-emerald-500/10 p-2">
                    <div className="mono text-[11px] font-bold text-emerald-400">0</div>
                    <div className="text-[10px] uppercase font-bold tracking-wide text-slate-500">Queue</div>
                  </div>
                  <div className="rounded-lg bg-[#06080F]/70 border border-emerald-500/10 p-2">
                    <div className="mono text-[11px] font-bold text-white">~1.2s</div>
                    <div className="text-[10px] uppercase font-bold tracking-wide text-slate-500">Avg run</div>
                  </div>
                </div>
              </div>
            </section>

            <section className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-stretch" id="trend-section">
              <div className="xl:col-span-2 rounded-2xl border border-slate-800 bg-[#0F1420] p-5 sm:p-6 flex flex-col h-full">
                <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
                  <h2 className="text-sm font-bold tracking-wide text-white flex items-center gap-2">
                    <span className="w-1 h-4 rounded-full bg-cyan-500" />
                    Security Posture Trend
                  </h2>
                  <div className="flex items-center gap-2 text-[11px] mono">
                    <span className="px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-300">
                      Runs: <b className="text-white">{trendPoints.length || 0}</b>
                    </span>
                    <span className="px-2.5 py-1 rounded-full bg-cyan-600 text-white font-bold">Posture {postureScore}</span>
                  </div>
                </div>

                {isLoading ? (
                  <div className="flex-1 min-h-[220px] rounded-xl bg-slate-900/50 border border-slate-800 animate-pulse" />
                ) : trendPoints.length === 0 ? (
                  <div className="flex-1 min-h-[220px] grid place-items-center rounded-xl border border-dashed border-slate-800 bg-[#06080F]">
                    <div className="text-center">
                      <div className="w-10 h-10 mx-auto rounded-xl bg-slate-900 border border-slate-800 grid place-items-center text-slate-500">
                        <Icon.Activity className="w-5 h-5" />
                      </div>
                      <div className="text-sm font-semibold text-slate-300 mt-3">No data yet</div>
                      <div className="text-xs text-slate-500 mt-1">Dispatch your first scenario to generate a trend.</div>
                    </div>
                  </div>
                ) : (
                  <div className="flex-1 rounded-xl border border-slate-800 bg-[#06080F] p-3 sm:p-4 overflow-hidden flex flex-col justify-center">
                    <div className="flex justify-between text-[10px] mono text-slate-600 px-2">
                      <span>0</span>
                      <span>25</span>
                      <span>50</span>
                      <span>75</span>
                      <span>100</span>
                    </div>
                    <div className="relative mt-2">
                      <div className="absolute inset-0 flex flex-col justify-between py-4 pointer-events-none">
                        {[0, 1, 2, 3, 4].map((i) => (
                          <div key={i} className="h-px bg-slate-800/60 w-full" />
                        ))}
                      </div>
                      <svg viewBox={`0 0 ${chart!.w} ${chart!.h}`} className="w-full h-[160px] relative">
                        <defs>
                          <linearGradient id="vanguardArea" x1="0" x2="0" y1="0" y2="1">
                            <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.35" />
                            <stop offset="100%" stopColor="#06b6d4" stopOpacity="0" />
                          </linearGradient>
                          <linearGradient id="vanguardLine" x1="0" x2="1" y1="0" y2="0">
                            <stop offset="0%" stopColor="#06b6d4" />
                            <stop offset="100%" stopColor="#6366f1" />
                          </linearGradient>
                        </defs>
                        {chart?.area && <path d={chart.area} fill="url(#vanguardArea)" stroke="none" />}
                        {chart?.path && (
                          <path d={chart.path} fill="none" stroke="url(#vanguardLine)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                        )}
                        {chart?.dots.map((d, i) => (
                          <g key={i}>
                            <circle cx={d.x} cy={d.y} r="10" fill="#06b6d4" opacity="0.12" />
                            <circle cx={d.x} cy={d.y} r="4" fill="white" stroke="#06b6d4" strokeWidth="2" />
                          </g>
                        ))}
                      </svg>
                    </div>
                    <div className="flex justify-between text-[10px] mono text-slate-500 px-2 mt-1">
                      <span>Run 0</span>
                      <span className="text-slate-400">Mid-audit</span>
                      <span className="text-emerald-400 font-bold">Secured {postureScore}</span>
                    </div>
                    <div className="grid grid-cols-3 gap-3 mt-4 pt-4 border-t border-slate-800">
                      <div>
                        <div className="text-[10px] font-bold tracking-widest uppercase text-slate-500">Lowest</div>
                        <div className="mono text-sm font-bold text-rose-400">{Math.min(...trendPoints)}/100</div>
                      </div>
                      <div>
                        <div className="text-[10px] font-bold tracking-widest uppercase text-slate-500">Delta</div>
                        <div className="mono text-sm font-bold text-emerald-400">
                          {trendPoints.length > 1 ? `+${trendPoints[trendPoints.length - 1] - trendPoints[0]}` : "+0"}
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-[10px] font-bold tracking-widest uppercase text-slate-500">Coverage</div>
                        <div className="mono text-sm font-bold text-white">{Object.keys(SCENARIOS).length} vectors</div>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <div className="rounded-2xl border border-slate-800 bg-[#0F1420] flex flex-col overflow-hidden h-full" id="inspector-panel">
                <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-[#0B0F1A]">
                  <h2 className="text-xs font-bold tracking-widest uppercase text-slate-300 flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse" />
                    Execution Inspector
                  </h2>
                  <span className="mono text-[11px] px-2 py-1 rounded-full bg-[#0E1626] border border-[#1E293B] text-cyan-300">
                    {activeInspector ? activeInspector.id.slice(0, 12) : "NO SELECTION"}
                  </span>
                </div>

                <div className="flex-1 p-5 custom-scrollbar overflow-auto">
                  {!activeInspector ? (
                    <div className="h-full grid place-items-center py-12 text-center">
                      <div>
                        <div className="w-12 h-12 mx-auto rounded-2xl bg-slate-900 border border-slate-800 grid place-items-center text-slate-600">
                          <Icon.Terminal className="w-6 h-6" />
                        </div>
                        <div className="text-sm font-semibold text-slate-300 mt-4">No episode selected</div>
                        <div className="text-xs text-slate-500 mt-1 max-w-[240px] mx-auto leading-relaxed">
                          Select a row from the ledger below or dispatch a new scenario to view telemetry, patch state and
                          advisory.
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="flex flex-wrap gap-2">
                        <span
                          className={cn(
                            "px-2.5 py-1 rounded-full border text-[11px] font-bold mono",
                            activeInspector.patch_applied
                              ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                              : "bg-rose-500/10 border-rose-500/20 text-rose-400"
                          )}
                        >
                          {activeInspector.patch_applied ? "● PATCH VERIFIED" : "● UNPATCHED"}
                        </span>
                        <span
                          className={cn(
                            "px-2.5 py-1 rounded-full border text-[11px] font-bold mono",
                            activeInspector.threat_flag
                              ? "bg-amber-500/10 border-amber-500/20 text-amber-300"
                              : "bg-slate-800 border-slate-700 text-slate-400"
                          )}
                        >
                          {activeInspector.threat_flag ? "⚑ THREAT CONFIRMED" : "✓ CLEAN"}
                        </span>
                        <span className="px-2.5 py-1 rounded-full bg-[#0E1626] border border-[#1E293B] mono text-[11px] font-bold text-white">
                          SCORE {activeInspector.score}
                        </span>
                      </div>

                      <div className="space-y-3">
                        <div>
                          <div className="text-[10px] font-bold tracking-widest uppercase text-slate-500 mb-1.5">
                            Attack Vector
                          </div>
                          <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-200 mono text-xs font-semibold">
                            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                            {activeInspector.attack_label || SCENARIOS[normalizeAttackKey(activeInspector.attack_type) as ScenarioKey]?.label || activeInspector.attack_type}
                            <span className="ml-auto text-[10px] px-1.5 py-0.5 rounded bg-cyan-600 text-white mono">
                              {SCENARIOS[normalizeAttackKey(activeInspector.attack_type) as ScenarioKey]?.owasp ?? activeInspector.attack_type ?? "—"}
                            </span>
                          </div>
                        </div>

                        <div>
                          <div className="text-[10px] font-bold tracking-widest uppercase text-slate-500 mb-1.5">
                            Target Endpoint
                          </div>
                          <div className="px-3 py-2.5 rounded-xl bg-[#06080F] border border-slate-800 mono text-xs text-cyan-300 break-all">
                            {activeInspector.target}
                          </div>
                        </div>

                        <div className="grid grid-cols-3 gap-2">
                          <div className="rounded-xl bg-[#06080F] border border-slate-800 p-3 text-center">
                            <div className="text-[10px] font-bold tracking-widest uppercase text-slate-500">Initial</div>
                            <div
                              className={cn(
                                "mono text-sm font-black mt-1",
                                activeInspector.status >= 400 ? "text-amber-400" : activeInspector.status >= 200 && activeInspector.status < 300 ? "text-emerald-400" : "text-rose-400"
                              )}
                            >
                              {activeInspector.status}
                            </div>
                            <div className="text-[10px] text-slate-600 mono">HTTP</div>
                          </div>
                          <div className="rounded-xl bg-[#06080F] border border-slate-800 p-3 text-center">
                            <div className="text-[10px] font-bold tracking-widest uppercase text-slate-500">Patch</div>
                            <div className={cn("mono text-xs font-black mt-1", activeInspector.patch_applied ? "text-emerald-400" : "text-rose-400")}>
                              {activeInspector.patch_applied ? "APPLIED" : "FAILED"}
                            </div>
                            <div className="text-[10px] text-slate-600 mono">auto</div>
                          </div>
                          <div className="rounded-xl bg-[#06080F] border border-slate-800 p-3 text-center">
                            <div className="text-[10px] font-bold tracking-widest uppercase text-slate-500">Re-Test</div>
                            <div className="mono text-sm font-black mt-1 text-emerald-400">{activeInspector.retest_status ?? "—"}</div>
                            <div className="text-[10px] text-slate-600 mono">verify</div>
                          </div>
                        </div>

                        <div>
                          <div className="flex items-center justify-between mb-1.5">
                            <span className="text-[10px] font-bold tracking-widest uppercase text-slate-500">Mitigation Advisory</span>
                            <span className="text-[10px] mono text-slate-600">{activeInspector.remediation.length} chars</span>
                          </div>
                          <div className="rounded-xl bg-[#06080F] border border-slate-800 p-3 max-h-[120px] overflow-auto custom-scrollbar">
                            <p className="text-xs leading-relaxed text-slate-300">{activeInspector.remediation}</p>
                          </div>
                        </div>

                        {activeInspector.pr_url && (
                          <div>
                            <div className="text-[10px] font-bold tracking-widest uppercase text-slate-500 mb-1.5">Git-Native Patch</div>
                            {activeInspector.pr_url.startsWith("http") ? (
                              <a
                                href={activeInspector.pr_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex items-center justify-between px-3 py-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 mono text-xs font-semibold hover:bg-emerald-500/20 transition-colors"
                              >
                                <span>VIEW PULL REQUEST</span>
                                <Icon.External className="w-3.5 h-3.5" />
                              </a>
                            ) : (
                              <div className="px-3 py-2.5 rounded-xl bg-slate-900 border border-slate-800 mono text-xs text-slate-500">
                                {activeInspector.pr_url}
                              </div>
                            )}
                          </div>
                        )}

                        <div className="rounded-xl border border-slate-800 overflow-hidden">
                          <button
                            onClick={() => setShowLogs((v) => !v)}
                            className="w-full flex items-center justify-between px-3 py-2.5 bg-slate-900/50 hover:bg-slate-900 transition-colors"
                          >
                            <span className="text-[11px] font-bold tracking-widest uppercase text-slate-400 flex items-center gap-2">
                              <Icon.Terminal className="w-3.5 h-3.5" />
                              Execution Logs
                              {activeInspector.logs?.length ? (
                                <span className="mono text-[11px] px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                                  {activeInspector.logs.length}
                                </span>
                              ) : null}
                            </span>
                            <Icon.Chevron className={cn("w-4 h-4 text-slate-500 transition-transform", showLogs && "rotate-180")} />
                          </button>
                          {showLogs && (
                            <div className="bg-[#06080F] border-t border-slate-800 max-h-[160px] overflow-auto p-3 mono text-[11px] leading-relaxed text-slate-400 custom-scrollbar">
                              {activeInspector.logs && activeInspector.logs.length > 0 ? (
                                <div className="space-y-1">
                                  {activeInspector.logs.map((l, i) => (
                                    <div key={i} className="flex gap-2">
                                      <span className="text-slate-600 select-none">{String(i + 1).padStart(2, "0")}</span>
                                      <span className="text-slate-300">{l}</span>
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <span className="italic text-slate-600">No logs captured for this run.</span>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {activeInspector && (
                  <div className="px-5 py-3 border-t border-slate-800 bg-[#0B0F1A] flex items-center justify-between">
                    <span className="text-[11px] mono text-slate-500">
                      Episode <b className="text-slate-300">{activeInspector.id}</b>
                    </span>
                    <button
                      onClick={() => navigator.clipboard.writeText(JSON.stringify(activeInspector, null, 2))}
                      className="text-[11px] font-bold tracking-wide px-2.5 py-1 rounded-lg bg-[#0E1626] border border-[#1E293B] text-slate-300 hover:text-white hover:border-[#334155]"
                    >
                      Copy JSON
                    </button>
                  </div>
                )}
              </div>
            </section>

            <section id="audit-history" className="rounded-2xl border border-slate-800 bg-[#0F1420] overflow-hidden">
              <div className="px-5 sm:px-6 py-4 border-b border-slate-800 flex flex-col lg:flex-row lg:items-center gap-4 justify-between">
                <div>
                  <h2 className="text-sm font-bold tracking-wide text-white flex items-center gap-2">
                    <span className="w-1 h-4 rounded-full bg-white" />
                    Audit & Hardening History
                    <span className="ml-2 mono text-[11px] font-bold px-2 py-0.5 rounded-full bg-slate-900 border border-slate-800 text-slate-400">
                      {filteredEpisodes.length} / {episodes.length}
                    </span>
                  </h2>
                  <p className="text-xs text-slate-500 mt-1">Latest first · Click Inspect to load execution inspector</p>
                </div>

                <div className="flex flex-col sm:flex-row gap-2 w-full lg:w-auto">
                  <div className="relative flex-1 sm:w-[280px]">
                    <Icon.Search className="w-4 h-4 text-slate-600 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Search id, vector, target..."
                      className="w-full pl-9 pr-3 py-2 rounded-xl bg-[#0E1626] border border-[#1E293B] focus:border-cyan-500/40 focus:ring-4 focus:ring-cyan-500/10 outline-none text-sm mono placeholder:text-slate-600"
                    />
                  </div>
                  <div className="flex items-center gap-1 p-1 rounded-xl bg-[#06080F] border border-slate-800 self-start">
                    {[
                      { k: "all", label: "All" },
                      { k: "threat", label: "Threats" },
                      { k: "patched", label: "Patched" },
                    ].map((f) => (
                      <button
                        key={f.k}
                        onClick={() => setStatusFilter(f.k as any)}
                        className={cn(
                          "px-3 py-1.5 rounded-lg text-xs font-bold transition-colors",
                          statusFilter === f.k ? "bg-white text-black shadow" : "text-slate-500 hover:text-slate-300"
                        )}
                      >
                        {f.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="overflow-x-auto custom-scrollbar">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-[#0B0F1A] border-b border-slate-800 text-[10px] font-bold tracking-widest uppercase text-slate-500">
                      <th className="py-3 px-4 whitespace-nowrap">ID</th>
                      <th className="py-3 px-4 whitespace-nowrap">Attack Vector</th>
                      <th className="py-3 px-4 whitespace-nowrap">Target</th>
                      <th className="py-3 px-4 whitespace-nowrap text-center">Init</th>
                      <th className="py-3 px-4 whitespace-nowrap text-center">Threat</th>
                      <th className="py-3 px-4 whitespace-nowrap text-center">Auto-Patch</th>
                      <th className="py-3 px-4 whitespace-nowrap text-center">Re-Test</th>
                      <th className="py-3 px-4 whitespace-nowrap text-center">Score</th>
                      <th className="py-3 px-4 whitespace-nowrap text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {isLoading ? (
                      Array.from({ length: 5 }).map((_, i) => (
                        <tr key={i} className="animate-pulse">
                          <td className="py-4 px-4">
                            <div className="h-3 w-20 bg-slate-800 rounded" />
                          </td>
                          <td className="py-4 px-4">
                            <div className="h-3 w-32 bg-slate-800 rounded" />
                          </td>
                          <td className="py-4 px-4">
                            <div className="h-3 w-40 bg-slate-800 rounded" />
                          </td>
                          <td colSpan={6} className="py-4 px-4">
                            <div className="h-3 w-full bg-slate-800 rounded" />
                          </td>
                        </tr>
                      ))
                    ) : filteredEpisodes.length === 0 ? (
                      <tr>
                        <td colSpan={9} className="py-16 text-center">
                          <div className="max-w-sm mx-auto">
                            <div className="w-12 h-12 mx-auto rounded-2xl bg-slate-900 border border-slate-800 grid place-items-center text-slate-600">
                              <Icon.Search className="w-6 h-6" />
                            </div>
                            <div className="text-sm font-semibold text-slate-300 mt-4">
                              {episodes.length === 0 ? "No simulations yet" : "No matches"}
                            </div>
                            <div className="text-xs text-slate-500 mt-1 leading-relaxed">
                              {episodes.length === 0
                                ? "Dispatch your first scenario above. The fleet will exploit, patch, and re-verify automatically."
                                : "Try adjusting filters or search. The ledger is queried client-side."}
                            </div>
                            {episodes.length === 0 && (
                              <button
                                onClick={() => document.querySelector<HTMLInputElement>('input[placeholder="http://127.0.0.1:8001"]')?.focus()}
                                className="mt-4 px-4 py-2 rounded-xl bg-white text-black text-xs font-bold"
                              >
                                Dispatch now
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ) : (
                      filteredEpisodes.map((ep) => {
                        const isActive = activeInspector?.id === ep.id;
                        const atkKey = normalizeAttackKey(ep.attack_type);
                        const scen = atkKey ? SCENARIOS[atkKey] : undefined;
                        const displayLabel = (ep as any).attack_label || scen?.label || ep.attack_type;
                        return (
                          <tr
                            key={ep.id}
                            className={cn(
                              "group transition-colors",
                              isActive ? "bg-cyan-500/[0.06] border-l-2 border-l-cyan-500" : "hover:bg-slate-900/50"
                            )}
                          >
                            <td className="py-3.5 px-4 whitespace-nowrap">
                              <span className="mono text-xs font-bold text-cyan-300">{ep.id.slice(0, 8)}</span>
                              <span className="mono text-[11px] text-slate-600 ml-1 hidden sm:inline">{ep.id.slice(8, 14)}</span>
                            </td>
                            <td className="py-3.5 px-4">
                              <div className="flex items-center gap-2">
                                <span
                                  className={cn(
                                    "w-1.5 h-1.5 rounded-full shrink-0",
                                    scen?.severity === "critical"
                                      ? "bg-rose-400 shadow-[0_0_6px_rgba(244,63,94,0.8)]"
                                      : scen?.severity === "high"
                                      ? "bg-amber-400"
                                      : "bg-cyan-400"
                                  )}
                                />
                                <span className="text-xs font-semibold text-slate-200 whitespace-nowrap">{displayLabel}</span>
                                {scen && (
                                  <span className="hidden lg:inline text-[10px] mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-500">
                                    {scen.owasp}
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="py-3.5 px-4 max-w-[220px]">
                              <span className="mono text-xs text-cyan-300/80 truncate block" title={ep.target}>
                                {ep.target}
                              </span>
                            </td>
                            <td className="py-3.5 px-4 text-center">
                              <span
                                className={cn(
                                  "mono text-xs font-bold px-2 py-1 rounded-full border",
                                  ep.status >= 500
                                    ? "bg-rose-500/10 border-rose-500/20 text-rose-300"
                                    : ep.status >= 400
                                    ? "bg-amber-500/10 border-amber-500/20 text-amber-300"
                                    : ep.status >= 200 && ep.status < 300
                                    ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-300"
                                    : "bg-slate-800 border-slate-700 text-slate-400"
                                )}
                              >
                                {ep.status}
                              </span>
                            </td>
                            <td className="py-3.5 px-4 text-center">
                              <span
                                className={cn(
                                  "inline-flex items-center gap-1 px-2 py-1 rounded-full border text-[11px] font-bold mono",
                                  ep.threat_flag
                                    ? "bg-amber-500/10 border-amber-500/20 text-amber-300"
                                    : "bg-slate-900 border-slate-800 text-slate-500"
                                )}
                              >
                                <span className={cn("w-1.5 h-1.5 rounded-full", ep.threat_flag ? "bg-amber-400" : "bg-slate-600")} />
                                {ep.threat_flag ? "Detected" : "Clean"}
                              </span>
                            </td>
                            <td className="py-3.5 px-4 text-center">
                              <span
                                className={cn(
                                  "inline-flex items-center gap-1 mono text-[11px] font-bold px-2 py-1 rounded-full border",
                                  ep.patch_applied
                                    ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-300"
                                    : "bg-slate-900 border-slate-800 text-slate-500"
                                )}
                              >
                                {ep.patch_applied ? <Icon.Check className="w-3 h-3" /> : null}
                                {ep.patch_applied ? "Active" : "None"}
                              </span>
                            </td>
                            <td className="py-3.5 px-4 text-center mono text-xs font-bold">
                              <span className={ep.retest_status === 403 || ep.retest_status === 401 ? "text-emerald-400" : "text-slate-400"}>
                                {ep.retest_status ?? "—"}
                              </span>
                            </td>
                            <td className="py-3.5 px-4 text-center">
                              <div className="flex items-center justify-center gap-2">
                                <div className="hidden sm:block w-14 h-1.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                                  <div
                                    className={cn(
                                      "h-full rounded-full",
                                      ep.score >= 80 ? "bg-emerald-500" : ep.score >= 60 ? "bg-amber-500" : "bg-rose-500"
                                    )}
                                    style={{ width: `${ep.score}%` }}
                                  />
                                </div>
                                <span className="mono text-xs font-bold text-white">{ep.score}</span>
                              </div>
                            </td>
                            <td className="py-3.5 px-4 text-right">
                              <button
                                onClick={() => setActiveInspector(ep)}
                                className={cn(
                                  "px-3 py-1.5 rounded-lg text-xs font-bold border transition-colors",
                                  isActive
                                    ? "bg-cyan-600 border-cyan-600 text-white shadow"
                                    : "bg-slate-900 border-slate-800 text-slate-300 hover:bg-white hover:text-black hover:border-white"
                                )}
                              >
                                Inspect
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              <div className="px-5 sm:px-6 py-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3 text-[11px] mono text-slate-500 bg-[#0B0F1A]">
                <span>
                  Showing <b className="text-slate-300">{filteredEpisodes.length}</b> of <b className="text-slate-300">{episodes.length}</b> episodes · Auto-refresh 5s
                </span>
                <span className="hidden sm:inline-flex items-center gap-2" suppressHydrationWarning>
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Fleet heartbeat · {heartbeat}
                </span>
              </div>
            </section>

            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] mono text-slate-600 border-t border-slate-800/60 pt-6">
              <span>
                © 2026 {BRAND.name} — Autonomous Security Operations Platform · Continuous loop v2.4 · SOC 2 Compliant
              </span>
              <span className="flex items-center gap-2">
                <span className="px-2 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-500">API: {API_DISPLAY}</span>
                <span className="hidden sm:inline">Latency ~18ms</span>
              </span>
            </div>
          </main>
          {/* Nav toast — non-intrusive */}
          {navToast && (
            <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 px-4 py-2.5 rounded-xl bg-[#0E1626] border border-[#1E293B] shadow-2xl flex items-center gap-2 text-sm text-slate-200 animate-in fade-in">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              {navToast}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
