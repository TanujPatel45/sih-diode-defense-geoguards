'use client';

import { useCallback, useEffect, useState } from 'react';
import { Activity, Cpu, Server } from 'lucide-react';
import { AreaChart, Area, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { API } from '../lib/api';
import type { Alert, Stats, TrendPoint } from '../lib/types';
import { TopBar } from '../components/TopBar';
import { KpiCard } from '../components/KpiCard';
import { SeverityBadge, RiskBar } from '../components/SeverityBadge';
import { AlertDrawer } from '../components/AlertDrawer';
import { EmptyState, LoadingState } from '../components/EmptyState';
import { HealthPanel } from '../components/HealthPanel';
import { ContinuousOperations } from '../components/ContinuousOperations';

const TOOLTIP_STYLE = {
  backgroundColor: 'var(--gg-surface)',
  border: '1px solid var(--gg-border)',
  borderRadius: 6, color: 'var(--gg-text)', fontSize: 11,
};

function fmtTime(iso: string) {
  try { return new Date(iso).toLocaleTimeString('en-GB', { hour12: false }); } catch { return iso; }
}
function proto(n: number) {
  return n === 6 ? 'TCP' : n === 17 ? 'UDP' : n === 1 ? 'ICMP' : String(n);
}

export default function LiveMonitor() {
  const [alerts,   setAlerts]   = useState<Alert[]>([]);
  const [stats,    setStats]    = useState<Stats | null>(null);
  const [trend,    setTrend]    = useState<TrendPoint[]>([]);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [loading,  setLoading]  = useState(true);

  const fetchAll = useCallback(async () => {
    try { setStats(await API.stats()); } catch { /* offline */ }
    try {
      const data = await API.alerts(50);
      if (!Array.isArray(data)) return;
      setAlerts(data);
      const now = Date.now();
      const pts: TrendPoint[] = [];
      for (let w = 11; w >= 0; w--) {
        const end = now - w * 30_000, start = end - 30_000;
        const label = new Date(end).toLocaleTimeString('en-GB', { hour12: false }).slice(0, 5);
        const threats = data.filter((a) => {
          const t = new Date(a.timestamp).getTime();
          return t >= start && t < end;
        }).length;
        pts.push({ time: label, threats, benign: 0 });
      }
      setTrend(pts);
    } catch { /* offline */ } finally { setLoading(false); }
  }, []);

  useEffect(() => {
    fetchAll();
    const id = setInterval(fetchAll, 3000);
    return () => clearInterval(id);
  }, [fetchAll]);

  const sorted = [...alerts].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  const latestSource = sorted[0]?.analysis_mode || stats?.last_alert_source || stats?.active_analysis_mode;
  const isPcap = latestSource === 'streaming_pcap_replay' || latestSource === 'pcap_replay';
  const isDemo = latestSource === 'demo_simulation' || latestSource === 'synthetic_demo';

  const SEV: Record<string, string> = {
    CRITICAL: 'var(--gg-red)', HIGH: 'var(--gg-orange)',
    MEDIUM: 'var(--gg-amber)', LOW: 'var(--gg-green)',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100%' }}>
      <TopBar title="Live Monitor" subtitle="Real-time passive telemetry · 3s polling · No active probing" />

      <div style={{ flex: 1, padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* KPIs */}
        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
          <KpiCard label="Flows Analysed" value={stats?.flows_processed ?? null}
            icon={<Activity size={16} />} iconColor="var(--gg-green)" />
          <KpiCard label="Threats" value={stats?.threats_detected ?? null}
            icon={<Server size={16} />} iconColor="var(--gg-red)" warning={(stats?.threats_detected ?? 0) > 0} />
          <KpiCard label="Anomalies" value={stats?.anomaly_count ?? null}
            icon={<Activity size={16} />} iconColor="var(--gg-amber)" />
          <KpiCard
            label="Avg Inference"
            value={stats?.average_inference_latency_ms != null ? stats.average_inference_latency_ms.toFixed(2) : null}
            unit={stats?.average_inference_latency_ms != null ? 'ms' : undefined}
            icon={<Cpu size={16} />} iconColor="var(--gg-cyan)"
            note="Target <2s" />
        </section>

        {/* Continuous Operations */}
        <ContinuousOperations onSelectAlert={setSelected} />

        {/* Risk trend */}
        <div className="gg-card" style={{ padding: 20 }}>
          <p className="gg-label" style={{ marginBottom: 14 }}>
            Risk Detections — Rolling 6-Minute Window (30s buckets)
          </p>
          <div style={{ height: 180 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend}>
                <defs>
                  <linearGradient id="mg" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#374151" fontSize={10} tickLine={false} />
                <YAxis stroke="#374151" fontSize={10} tickLine={false} allowDecimals={false} width={22} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Area type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2}
                  fill="url(#mg)" dot={false} name="Detections" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Alert stream + health */}
        <section style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
          <div className="gg-card" style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <p className="gg-label" style={{ margin: 0 }}>Current Alert Stream</p>
              {latestSource && (
                <span style={{
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: '0.04em',
                  padding: '3px 10px',
                  borderRadius: 14,
                  background: isPcap ? 'rgba(168, 85, 247, 0.12)' : isDemo ? 'rgba(245, 158, 11, 0.12)' : 'rgba(16, 185, 129, 0.12)',
                  border: `1px solid ${isPcap ? 'rgba(168, 85, 247, 0.4)' : isDemo ? 'rgba(245, 158, 11, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`,
                  color: isPcap ? '#c084fc' : isDemo ? '#fbbf24' : '#34d399',
                  textTransform: 'uppercase',
                }}>
                  {isPcap ? 'Data Source: PCAP Replay' : isDemo ? 'Data Source: Demo Simulation' : 'Data Source: Live Ingest'}
                </span>
              )}
            </div>
            {loading ? (
              <LoadingState message="Polling backend…" />
            ) : sorted.length === 0 ? (
              <EmptyState
                title="NO ACTIVE THREATS"
                message="Monitoring passive telemetry. No threats detected in recent polling window."
              />
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--gg-border)' }}>
                      {['Time', 'Src → Dst', 'Proto', 'Threat', 'Risk', 'Sev'].map((h) => (
                        <th key={h} style={{ padding: '0 8px 8px 0', fontSize: 10, fontWeight: 600,
                          letterSpacing: '0.08em', textTransform: 'uppercase' as const,
                          color: 'var(--gg-muted)', textAlign: 'left' as const }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sorted.map((a) => (
                      <tr key={a.alert_id}
                        onClick={() => setSelected(a)}
                        style={{ borderBottom: '1px solid rgba(31,41,55,0.4)', cursor: 'pointer' }}
                        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--gg-surface-2)')}
                        onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                      >
                        <td style={{ padding: '8px 8px 8px 0', fontSize: 11, color: 'var(--gg-muted)', fontFamily: 'var(--font-mono)' }}>
                          {fmtTime(a.timestamp)}
                        </td>
                        <td style={{ padding: '8px 8px 8px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>
                          {a.source_ip} → {a.destination_ip}
                        </td>
                        <td style={{ padding: '8px 8px 8px 0', fontSize: 11, color: 'var(--gg-muted)' }}>{proto(a.protocol)}</td>
                        <td style={{ padding: '8px 8px 8px 0' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                            <span style={{ fontSize: 11, fontWeight: 600, color: SEV[a.severity] ?? 'var(--gg-text-2)' }}>
                              {a.dominant_threat}
                            </span>
                            <span style={{ fontSize: 9, color: 'var(--gg-muted)', letterSpacing: '0.02em' }}>
                              Source: {
                                a.analysis_mode === 'streaming_pcap_replay' ? 'PCAP Replay' :
                                a.analysis_mode === 'demo_simulation' ? 'Demo Simulation' :
                                'Live Ingest'
                              }
                            </span>
                          </div>
                        </td>
                        <td style={{ padding: '8px 8px 8px 0', minWidth: 90 }}>
                          <RiskBar score={a.final_risk_score} severity={a.severity} />
                        </td>
                        <td style={{ padding: '8px 0' }}><SeverityBadge severity={a.severity} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          <HealthPanel />
        </section>
      </div>

      {selected && <AlertDrawer alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
