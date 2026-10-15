import {
  Activity,
  AlertOctagon,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clock3,
  Command,
  FileClock,
  Fingerprint,
  Globe2,
  KeyRound,
  LoaderCircle,
  LogOut,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { request } from "./api";
import type { Incident, IncidentDetail, SecurityEvent, Summary, User } from "./types";

const DEMO_EMAIL = "admin@sentinel.local";

function timeAgo(value: string): string {
  const minutes = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 60_000));
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function label(value: string): string {
  return value.replaceAll("_", " ");
}

function Login({ onLogin }: { onLogin: (token: string, user: User) => void }) {
  const [email, setEmail] = useState(DEMO_EMAIL);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      const result = await request<{ access_token: string; user: User }>("/auth/login", undefined, {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      onLogin(result.access_token, result.user);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to sign in");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page">
      <div className="login-orbit orbit-one" />
      <div className="login-orbit orbit-two" />
      <section className="login-card">
        <div className="brand-mark large"><Shield size={24} /></div>
        <p className="eyebrow">SECURITY OPERATIONS CENTER</p>
        <h1>See the signal.<br /><span>Stop the threat.</span></h1>
        <p className="login-copy">Sign in to your organization’s threat intelligence workspace.</p>
        <form onSubmit={submit} className="login-form">
          <label htmlFor="email">Work email</label>
          <input id="email" type="email" autoComplete="username" value={email} onChange={(event) => setEmail(event.target.value)} required />
          <label htmlFor="password">Password</label>
          <input id="password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required />
          {error && <p className="form-error">{error}</p>}
          <button className="primary-button login-button" disabled={busy}>
            {busy ? <LoaderCircle className="spin" size={17} /> : <KeyRound size={17} />}
            Secure sign in
          </button>
        </form>
        <div className="login-foot"><Fingerprint size={15} /> Protected with role-based access</div>
      </section>
      <div className="login-caption"><span className="live-dot" /> SENTINEL THREAT INTELLIGENCE <span>•</span> SYSTEMS OPERATIONAL</div>
    </main>
  );
}

function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("sentinel-token"));
  const [user, setUser] = useState<User | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selected, setSelected] = useState<IncidentDetail | null>(null);
  const [statusFilter, setStatusFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  const loadDashboard = useCallback(async (activeToken: string) => {
    setRefreshing(true);
    try {
      const [nextSummary, nextIncidents] = await Promise.all([
        request<Summary>("/summary", activeToken),
        request<Incident[]>("/incidents", activeToken),
      ]);
      setSummary(nextSummary);
      setIncidents(nextIncidents);
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load security data");
    } finally {
      setRefreshing(false);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }
    let active = true;
    Promise.all([request<User>("/auth/me", token), request<Summary>("/summary", token), request<Incident[]>("/incidents", token)])
      .then(([nextUser, nextSummary, nextIncidents]) => {
        if (!active) return;
        setUser(nextUser);
        setSummary(nextSummary);
        setIncidents(nextIncidents);
        setError("");
      })
      .catch((cause: unknown) => {
        if (!active) return;
        setError(cause instanceof Error ? cause.message : "Unable to load security data");
        if (cause instanceof Error && cause.message.includes("token")) signOut();
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, [token]);

  useEffect(() => {
    if (!token || !selected) return;
    let active = true;
    request<IncidentDetail>(`/incidents/${selected.id}`, token)
      .then((detail) => { if (active) setSelected(detail); })
      .catch((cause: unknown) => {
        if (active) setError(cause instanceof Error ? cause.message : "Unable to load incident");
      });
    return () => { active = false; };
  }, [token, selected?.id]);

  useEffect(() => {
    if (!token) return;
    const interval = window.setInterval(() => {
      void loadDashboard(token);
    }, 60_000);
    return () => window.clearInterval(interval);
  }, [token, loadDashboard]);

  function signOut() {
    localStorage.removeItem("sentinel-token");
    setToken(null);
    setUser(null);
    setSelected(null);
    setSummary(null);
    setIncidents([]);
  }

  function acceptLogin(nextToken: string, nextUser: User) {
    localStorage.setItem("sentinel-token", nextToken);
    setToken(nextToken);
    setUser(nextUser);
    setLoading(true);
  }

  async function updateStatus(incident: IncidentDetail, nextStatus: Incident["status"]) {
    if (!token) return;
    try {
      const updated = await request<Incident>(`/incidents/${incident.id}`, token, {
        method: "PATCH",
        body: JSON.stringify({ status: nextStatus }),
      });
      setSelected({ ...incident, ...updated });
      await loadDashboard(token);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to update incident");
    }
  }

  const filteredIncidents = useMemo(() => incidents.filter((incident) => {
    const matchesStatus = statusFilter === "all" || incident.status === statusFilter;
    const matchesSeverity = severityFilter === "all" || incident.severity === severityFilter;
    const matchesSearch = `${incident.title} ${incident.description}`.toLowerCase().includes(search.toLowerCase());
    return matchesStatus && matchesSeverity && matchesSearch;
  }), [incidents, search, severityFilter, statusFilter]);

  if (!token || !user) {
    if (token && loading) return <div className="loading-screen"><LoaderCircle className="spin" size={22} /><span>Securing your workspace…</span></div>;
    return <Login onLogin={acceptLogin} />;
  }
  if (loading) return <div className="loading-screen"><LoaderCircle className="spin" size={22} /><span>Loading threat intelligence…</span></div>;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand"><div className="brand-mark"><Shield size={19} /></div><span>sentinel<span className="brand-period">.</span></span><span className="brand-tag">SOC</span></div>
        <div className="workspace-switch"><div className="workspace-logo">A</div><div><strong>Acme Corporation</strong><small>Enterprise workspace</small></div><ChevronDown size={15} /></div>
        <p className="nav-label">WORKSPACE</p>
        <button className="nav-item active"><Activity size={17} /> Overview <span className="nav-active-line" /></button>
        <button className="nav-item" onClick={() => document.getElementById("incidents")?.scrollIntoView({ behavior: "smooth" })}><ShieldAlert size={17} /> Incidents <span className="nav-count">{summary?.open_incidents ?? 0}</span></button>
        <button className="nav-item" onClick={() => document.getElementById("event-stream")?.scrollIntoView({ behavior: "smooth" })}><FileClock size={17} /> Event stream</button>
        <button className="nav-item" onClick={() => setError("Audit records are available from the admin-only /api/audit endpoint.")}><Fingerprint size={17} /> Audit trail</button>
        <p className="nav-label nav-label-lower">MANAGE</p>
        <button className="nav-item" onClick={() => setError("Detection rules are configured in the backend for this MVP.")}><SlidersHorizontal size={17} /> Detection rules</button>
        <button className="nav-item" onClick={() => setError("Workspace settings are not part of this MVP.")}><CircleHelp size={17} /> Help &amp; settings</button>
        <div className="sidebar-bottom">
          <div className="system-status"><span className="live-dot" /><span>All systems operational</span><ChevronRight size={14} /></div>
          <div className="user-card"><div className="avatar">{user.email.slice(0, 1).toUpperCase()}</div><div className="user-meta"><strong>{user.email.split("@")[0]}</strong><small>{user.role} · Acme Corp</small></div><button className="icon-button" title="Sign out" onClick={signOut}><LogOut size={16} /></button></div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">Workspace <ChevronRight size={14} /> <strong>Overview</strong></div>
          <div className="top-actions"><div className="environment-pill"><span /> Production environment</div><button className="top-icon" title="Notifications"><Bell size={18} /><i /></button><div className="top-avatar">{user.email.slice(0, 1).toUpperCase()}</div></div>
        </header>
        <div className="page-content">
          <section className="page-heading">
            <div><p className="eyebrow">THURSDAY, OCTOBER 15, 2026 <span>•</span> SOC OVERVIEW</p><h1>Good morning, {user.email.split("@")[0]}</h1><p className="subheading">Here’s what’s happening across your security environment.</p></div>
            <div className="heading-actions"><button className="secondary-button" onClick={() => token && loadDashboard(token)} disabled={refreshing}><Activity size={15} className={refreshing ? "spin" : ""} /> Refresh</button><div className="range-pill"><Clock3 size={15} /> Last 24 hours <ChevronDown size={14} /></div></div>
          </section>
          {error && <div className="inline-error"><AlertOctagon size={16} />{error}<button onClick={() => setError("")}><X size={15} /></button></div>}
          <section className="metrics-grid">
            <MetricCard title="Open incidents" value={summary?.open_incidents ?? 0} note="Needs investigation" icon={<ShieldAlert size={18} />} tone="violet" trend="+12.5%" positive={false} />
            <MetricCard title="Critical severity" value={summary?.critical_incidents ?? 0} note="Immediate attention" icon={<AlertOctagon size={18} />} tone="red" trend="−8.2%" positive />
            <MetricCard title="High severity" value={summary?.high_incidents ?? 0} note="Elevated risk" icon={<ShieldCheck size={18} />} tone="amber" trend="+4.3%" positive={false} />
            <MetricCard title="Events analyzed" value={(summary?.events_24h ?? 0).toLocaleString()} note="Across all sources" icon={<Globe2 size={18} />} tone="blue" trend="+18.6%" positive />
          </section>

          <section className="insight-banner">
            <div className="insight-icon"><Command size={18} /></div><div className="insight-copy"><strong>Security posture is holding steady</strong><span>Sentinel analyzed {summary?.events_24h ?? 0} events in the last 24 hours and surfaced {summary?.open_incidents ?? 0} incidents for review.</span></div><div className="insight-spark"><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /></div><button onClick={() => document.getElementById("incidents")?.scrollIntoView({ behavior: "smooth" })}>Review incidents <ChevronRight size={15} /></button>
          </section>

          <section className="panel incidents-panel" id="incidents">
            <div className="panel-header"><div><div className="panel-title-line"><h2>Priority incidents</h2><span className="count-badge">{filteredIncidents.length}</span></div><p>Investigate and respond to detected threats</p></div><button className="text-button" onClick={() => setStatusFilter("all")}>View all incidents <ChevronRight size={15} /></button></div>
            <div className="filters-row"><div className="search-field"><Search size={16} /><input aria-label="Search incidents" placeholder="Search incidents…" value={search} onChange={(event) => setSearch(event.target.value)} /><kbd>⌘ K</kbd></div><label className="select-wrap"><span className="sr-only">Filter by status</span><select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option value="all">All statuses</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select><ChevronDown size={14} /></label><label className="select-wrap"><span className="sr-only">Filter by severity</span><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><ChevronDown size={14} /></label><button className="filter-button" title="Filters"><SlidersHorizontal size={16} /></button></div>
            <div className="incident-table-wrap"><table className="incident-table"><thead><tr><th>INCIDENT</th><th>SEVERITY</th><th>RISK SCORE</th><th>STATUS</th><th>EVENTS</th><th>DETECTED</th><th /></tr></thead><tbody>
              {filteredIncidents.map((incident) => <tr key={incident.id} onClick={() => setSelected({ ...incident, events: [] })} className="incident-row"><td><div className="incident-name"><span className={`severity-marker ${incident.severity}`} /><div><strong>{incident.title}</strong><small>INC-{String(incident.id).padStart(4, "0")} <span>·</span> {incident.rule_key}</small></div></div></td><td><span className={`severity-pill ${incident.severity}`}><span />{incident.severity}</span></td><td><div className="risk-cell"><div className="risk-track"><span className={incident.severity} style={{ width: `${incident.risk_score}%` }} /></div><strong>{incident.risk_score}</strong></div></td><td><span className={`status-pill ${incident.status}`}>{incident.status}</span></td><td><span className="event-count"><FileClock size={14} />{incident.event_count}</span></td><td className="muted-cell">{timeAgo(incident.created_at)}</td><td><button className="row-open" aria-label={`Open ${incident.title}`}><ChevronRight size={16} /></button></td></tr>)}
              {filteredIncidents.length === 0 && <tr><td colSpan={7} className="empty-state">No incidents match these filters.</td></tr>}
            </tbody></table></div>
            <div className="table-footer"><span>Showing <strong>{filteredIncidents.length}</strong> of <strong>{incidents.length}</strong> incidents</span><div><button disabled>Previous</button><button className="page-current">1</button><button disabled>Next</button></div></div>
          </section>

          <div className="bottom-grid">
            <section className="panel event-panel" id="event-stream"><div className="panel-header compact"><div><h2>Live event stream</h2><p>Latest signals from connected sources</p></div><span className="stream-live"><i /> LIVE</span></div><div className="event-list">{(summary?.recent_events ?? []).slice(0, 5).map((event) => <EventRow key={event.id} event={event} />)}{!summary?.recent_events.length && <div className="empty-state">No recent events.</div>}</div><button className="event-footer" onClick={() => token && loadDashboard(token)}>View event stream <ChevronRight size={15} /></button></section>
            <section className="panel sources-panel"><div className="panel-header compact"><div><h2>Connected sources</h2><p>Telemetry ingestion status</p></div><span className="source-total">3 sources</span></div><div className="source-list"><SourceRow name="Identity provider" type="Authentication logs" events="1.2k" icon="ID" color="purple" /><SourceRow name="Endpoint agent" type="Endpoint telemetry" events="842" icon="EP" color="cyan" /><SourceRow name="Web gateway" type="Application logs" events="516" icon="WG" color="orange" /></div><div className="source-foot"><span><i /> All sources healthy</span><button onClick={() => setError("Connectors are not part of this MVP.")}>Manage sources <ChevronRight size={14} /></button></div></section>
          </div>
          <footer className="page-footer"><span>Sentinel Security Intelligence <span>·</span> MVP 0.1.0</span><span><span className="live-dot" /> Data refreshing automatically</span></footer>
        </div>
      </main>
      {selected && <IncidentDrawer incident={selected} canUpdate={user.role !== "viewer"} onClose={() => setSelected(null)} onStatusChange={(nextStatus) => updateStatus(selected, nextStatus)} />}
    </div>
  );
}

function MetricCard({ title, value, note, icon, tone, trend, positive }: { title: string; value: string | number; note: string; icon: ReactNode; tone: string; trend: string; positive: boolean }) {
  return <article className="metric-card"><div className={`metric-icon ${tone}`}>{icon}</div><div className="metric-trend">{positive ? <ArrowDownRight size={14} /> : <ArrowUpRight size={14} />}{trend}</div><span className="metric-title">{title}</span><strong className="metric-value">{value}</strong><span className="metric-note">{note}</span></article>;
}

function EventRow({ event }: { event: SecurityEvent }) {
  const isThreat = event.severity === "critical" || event.severity === "high";
  return <div className="event-row"><div className={`event-icon ${isThreat ? "threat" : "normal"}`}>{isThreat ? <ShieldAlert size={15} /> : <Activity size={15} />}</div><div className="event-description"><strong>{label(event.event_type)}</strong><span>{event.message}</span></div><span className={`mini-severity ${event.severity}`}>{event.severity}</span><time>{timeAgo(event.timestamp)}</time></div>;
}

function SourceRow({ name, type, events, icon, color }: { name: string; type: string; events: string; icon: string; color: string }) {
  return <div className="source-row"><div className={`source-icon ${color}`}>{icon}</div><div className="source-name"><strong>{name}</strong><span>{type}</span></div><div className="source-events"><strong>{events}</strong><span>events / day</span></div><span className="source-health"><i /></span></div>;
}

function IncidentDrawer({ incident, canUpdate, onClose, onStatusChange }: { incident: IncidentDetail; canUpdate: boolean; onClose: () => void; onStatusChange: (status: Incident["status"]) => void }) {
  const nextStatus: Incident["status"] = incident.status === "open" ? "investigating" : incident.status === "investigating" ? "resolved" : "open";
  return <div className="drawer-backdrop" onClick={onClose}><aside className="incident-drawer" onClick={(event) => event.stopPropagation()}><header className="drawer-header"><div><span className="eyebrow">INC-{String(incident.id).padStart(4, "0")} <span>·</span> INCIDENT DETAILS</span><h2>{incident.title}</h2></div><button className="icon-button" aria-label="Close incident details" onClick={onClose}><X size={18} /></button></header><div className="drawer-scroll"><div className="drawer-badges"><span className={`severity-pill ${incident.severity}`}><span />{incident.severity} severity</span><span className={`status-pill ${incident.status}`}>{incident.status}</span></div><p className="drawer-description">{incident.description}</p><div className="risk-summary"><div><span>Risk score</span><strong>{incident.risk_score}<small> / 100</small></strong></div><div className="risk-track"><span className={incident.severity} style={{ width: `${incident.risk_score}%` }} /></div></div><div className="detail-grid"><div><span>Detection rule</span><strong>{incident.rule_key}</strong></div><div><span>Related events</span><strong>{incident.event_count}</strong></div><div><span>First detected</span><strong>{new Date(incident.created_at).toLocaleString()}</strong></div><div><span>Last updated</span><strong>{new Date(incident.updated_at).toLocaleString()}</strong></div></div><div className="timeline-heading"><div><h3>Investigation timeline</h3><p>Correlated event evidence</p></div><span>{incident.events.length} EVENTS</span></div><div className="timeline">{incident.events.map((event) => <div className="timeline-item" key={event.id}><div className="timeline-dot" /><time>{new Date(event.timestamp).toLocaleString()}</time><strong>{label(event.event_type)}</strong><p>{event.message}</p><div className="timeline-meta"><span><Globe2 size={13} />{event.source_ip || "IP unavailable"}</span><span>{event.host}</span></div></div>)}{incident.events.length === 0 && <div className="timeline-empty">No event evidence is linked to this incident yet.</div>}</div></div>{canUpdate && <footer className="drawer-footer"><button className="secondary-button" onClick={onClose}>Close</button><button className="primary-button" onClick={() => onStatusChange(nextStatus)}>{incident.status === "open" ? <Activity size={15} /> : incident.status === "investigating" ? <Check size={15} /> : <ShieldCheck size={15} />}{incident.status === "open" ? "Start investigation" : incident.status === "investigating" ? "Resolve incident" : "Reopen incident"}</button></footer>}</aside></div>;
}

export default App;
