'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  ResponsiveContainer, Tooltip, XAxis, YAxis, Legend,
} from 'recharts';
import { API } from '../lib/api';
import type { Alert, Stats } from '../lib/types';
import { TopBar } from '../components/TopBar';
import { EmptyState, LoadingState } from '../components/EmptyState';

const TOOLTIP_STYLE = {
  backgroundColor: 'var(--gg-surface)',
  border: '1px solid var(--gg-border)',
  borderRadius: 6, color: 'var(--gg-text)', fontSize: 11,
};

const THREAT_COLORS: Record<string, string> = {
  'SYN/UDP Flood': '#ef4444', 'DNS Tunneling': '#06b6d4',
  'C2 Beaconing': '#f97316', 'Anomaly': '#f59e0b', 'Benign': '#22c55e',
};

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#22c55e',
};

function ChartCard({ title, children, empty }: { title: string; children: React.ReactNode; empty?: boolean }) {
  return (
    <div className="gg-card" style={{ padding: 20 }}>
      <p className="gg-label" style={{ marginBottom: 14 }}>{title}</p>
      {empty ? (
        <EmptyState title="INSUFFICIENT HISTORICAL DATA" message="Not enough data points to render this chart." />
      ) : children}
    </div>
  );
}

export default function Analytics() {
  const [alerts,  setAlerts]  = useState<Alert[]>([]);
  const [stats,   setStats]   = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try { setStats(await API.stats()); } catch { /* offline */ }
    try {
      const data = await API.alerts(500);
      if (Array.isArray(data)) setAlerts(data);
    } catch { /* offline */ } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Risk over time (30-min bins)
  const now = Date.now();
  const BINS = 24; // last 12 hours × 30-min bins
  const riskOverTime = Array.from({ length: BINS }, (_, i) => {
    const end   = now - (BINS - 1 - i) * 30 * 60_000;
    const start = end - 30 * 60_000;
    const label = new Date(end).toLocaleTimeString('en-GB', { hour12: false }).slice(0, 5);
    const bucket = alerts.filter((a) => {
      const t = new Date(a.timestamp).getTime();
      return t >= start && t < end;
    });
    const avg = bucket.length > 0
      ? bucket.reduce((s, a) => s + a.final_risk_score, 0) / bucket.length
      : null;
    return { time: label, risk: avg !== null ? parseFloat((avg * 100).toFixed(1)) : null, count: bucket.length };
  });

  // Threat distribution
  const threatDist: Record<string, number> = {};
  for (const a of alerts) {
    const k = a.dominant_threat || 'Unknown';
    threatDist[k] = (threatDist[k] || 0) + 1;
  }
  const threatPie = Object.entries(threatDist).map(([name, value]) => ({ name, value }));

  // Severity distribution
  const sevDist: Record<string, number> = {};
  for (const a of alerts) { sevDist[a.severity] = (sevDist[a.severity] || 0) + 1; }
  const sevBar = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => ({ name: s, count: sevDist[s] ?? 0 }));

  // Top source IPs
  const srcIps: Record<string, number> = {};
  for (const a of alerts) { srcIps[a.source_ip] = (srcIps[a.source_ip] || 0) + 1; }
  const topSrc = Object.entries(srcIps)
    .sort(([, a], [, b]) => b - a).slice(0, 8)
    .map(([ip, count]) => ({ ip, count }));

  // Pillar contribution
  const pillarAvg = alerts.length > 0 ? {
    Supervised:  parseFloat((alerts.reduce((s, a) => s + a.confidence, 0) / alerts.length * 100).toFixed(1)),
    Anomaly:     parseFloat((alerts.reduce((s, a) => s + a.anomaly_score, 0) / alerts.length * 100).toFixed(1)),
    Behaviour:   parseFloat((alerts.reduce((s, a) => s + a.behaviour_score, 0) / alerts.length * 100).toFixed(1)),
  } : null;

  if (loading) return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100%' }}>
      <TopBar title="Analytics" subtitle="Historical analysis · Actual API data only" />
      <div style={{ flex: 1, padding: 24 }}><LoadingState /></div>
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100%' }}>
      <TopBar title="Analytics" subtitle="Historical analysis · Actual API data only · No manufactured data" />

      <div style={{ flex: 1, padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Stats strip */}
        {stats && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Flows', value: stats.flows_processed },
              { label: 'Threats', value: stats.threats_detected },
              { label: 'High-Risk', value: stats.high_risk_alerts },
              { label: 'Anomalies', value: stats.anomaly_count },
              { label: 'Alerts Loaded', value: alerts.length },
            ].map((s) => (
              <div key={s.label} className="gg-card" style={{ padding: '14px 16px' }}>
                <p className="gg-label" style={{ marginBottom: 6 }}>{s.label}</p>
                <p style={{ fontSize: 22, fontWeight: 700, color: 'var(--gg-text)' }}>{s.value}</p>
              </div>
            ))}
          </div>
        )}

        {/* Risk over time + Severity dist */}
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
          <ChartCard title="Average Risk Score Over Time (30-min bins)" empty={!riskOverTime.some((p) => p.risk !== null)}>
            <div style={{ height: 180 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={riskOverTime}>
                  <defs>
                    <linearGradient id="rg" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#f97316" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#374151" fontSize={10} tickLine={false} interval={3} />
                  <YAxis stroke="#374151" fontSize={10} tickLine={false} domain={[0, 100]} width={28} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(v) => [`${v}`, 'Avg Risk']} />
                  <Area type="monotone" dataKey="risk" stroke="#f97316" strokeWidth={2}
                    fill="url(#rg)" dot={false} connectNulls name="Avg Risk" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>

          <ChartCard title="Severity Distribution" empty={sevBar.every((s) => s.count === 0)}>
            <div style={{ height: 180 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={sevBar} barCategoryGap="30%">
                  <XAxis dataKey="name" stroke="#374151" fontSize={9} tickLine={false} />
                  <YAxis stroke="#374151" fontSize={10} tickLine={false} allowDecimals={false} width={22} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                    {sevBar.map((s) => (
                      <Cell key={s.name} fill={SEV_COLORS[s.name] ?? '#6b7280'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
        </div>

        {/* Threat dist + Top IPs + Pillar contribution */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
          <ChartCard title="Threat Class Distribution" empty={threatPie.length === 0}>
            <div style={{ height: 160 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={threatPie} cx="50%" cy="50%" innerRadius={40} outerRadius={62}
                    dataKey="value" paddingAngle={3}>
                    {threatPie.map((e) => (
                      <Cell key={e.name} fill={THREAT_COLORS[e.name] ?? '#6b7280'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Legend iconSize={8} wrapperStyle={{ fontSize: 10 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>

          <ChartCard title="Top Source IPs by Alert Count" empty={topSrc.length === 0}>
            <div style={{ height: 160 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topSrc} layout="vertical" barCategoryGap="20%">
                  <XAxis type="number" stroke="#374151" fontSize={9} tickLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="ip" stroke="#374151" fontSize={9} tickLine={false} width={110}
                    tick={{ fontFamily: 'var(--font-mono)', fontSize: 10 }} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="count" fill="var(--gg-cyan)" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>

          <ChartCard title="Avg Detection Pillar Score" empty={!pillarAvg}>
            {pillarAvg && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14, paddingTop: 8 }}>
                {[
                  { label: 'Supervised (50%)', value: pillarAvg.Supervised, color: 'var(--gg-cyan)' },
                  { label: 'Anomaly (25%)',    value: pillarAvg.Anomaly,    color: 'var(--gg-amber)' },
                  { label: 'Behaviour (25%)',  value: pillarAvg.Behaviour,  color: 'var(--gg-orange)' },
                ].map((p) => (
                  <div key={p.label}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 6 }}>
                      <span style={{ color: 'var(--gg-text-2)' }}>{p.label}</span>
                      <span style={{ color: p.color, fontWeight: 700 }}>{p.value}%</span>
                    </div>
                    <div style={{ height: 5, background: 'var(--gg-surface-2)', borderRadius: 3 }}>
                      <div style={{ height: '100%', width: `${p.value}%`, background: p.color, borderRadius: 3 }} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </ChartCard>
        </div>
      </div>
    </div>
  );
}
