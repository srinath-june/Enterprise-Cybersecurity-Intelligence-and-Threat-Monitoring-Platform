export type User = {
  id: number;
  email: string;
  role: "viewer" | "analyst" | "admin";
};

export type SecurityEvent = {
  id: number;
  timestamp: string;
  source: string;
  host: string;
  username: string;
  event_type: string;
  source_ip: string;
  severity: string;
  message: string;
  incident_id: number | null;
};

export type Incident = {
  id: number;
  title: string;
  description: string;
  severity: string;
  risk_score: number;
  status: "open" | "investigating" | "resolved";
  rule_key: string;
  created_at: string;
  updated_at: string;
  event_count: number;
};

export type IncidentDetail = Incident & { events: SecurityEvent[] };

export type Summary = {
  open_incidents: number;
  critical_incidents: number;
  high_incidents: number;
  events_24h: number;
  recent_events: SecurityEvent[];
};
