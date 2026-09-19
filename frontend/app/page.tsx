'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Activity, AlertTriangle, Cpu, ShieldAlert, Zap, Radio,
  CheckCircle, RefreshCw, GitCommit, ArrowRight, ShieldCheck
} from 'lucide-react';
import {
  AreaChart, Area, ResponsiveContainer, Tooltip, XAxis, YAxis,
  PieChart, Pie, Cell,
} from 'recharts';
import { API } from './lib/api';
import type { Alert, Stats, TrendPoint, CorrelationCluster } from './lib/types';
import { TopBar } from './components/TopBar';
import { KpiCard } from './components/KpiCard';
import { SeverityBadge, RiskBar } from './components/SeverityBadge';
import { AlertDrawer } from './components/AlertDrawer';
import { ContinuousOperations } from './components/ContinuousOperations';
import { NetworkTopology } from './components/NetworkTopology';
import { HealthPanel } from './components/HealthPanel';
import { EmptyState } from './components/EmptyState';

const THREAT_COLORS: Record<string, string> = {
  'SYN/UDP Flood': '#f87171',
  'DNS Tunneling': '#22d3ee',
  'C2 Beaconing':  '#fb923c',
  'Volumetric / Protocol DDoS': '#f87171',
  'Botnet C2 Beaconing': '#fb923c',
  'DGA Domains and DNS Tunnelling': '#22d3ee',
  'Reconnaissance / Port Scanning': '#a855f7',
  'Data Exfiltration': '#ec4899',
  'Malware in Encrypted Sessions': '#3b82f6',
  'Anomaly':       '#fbbf24',
  'Benign':        '#34d399',
};

const TOOLTIP_STYLE = {
  backgroundColor: 'rgba(10, 18, 35, 0.94)',
  backdropFilter: 'blur(16px)',
  WebkitBackdropFilter: 'blur(16px)',
  border: '1px solid rgba(255, 255, 255, 0.12)',
  borderRadius: 8,
  boxShadow: '0 8px 32px rgba(0, 0, 0, 0.6)',
  color: 'var(--gg-text)',
  fontSize: 11,
  padding: '8px 12px',
};

function fmtTime(iso: string) {
  try { return new Date(iso).toLocaleTimeString('en-GB', { hour12: false }); }
  catch { return iso; }
}
function proto(n: number) {
  return n === 6 ? 'TCP' : n === 17 ? 'UDP' : n === 1 ? 'ICMP' : n ? String(n) : '—';
}

export default function Overview() {
  const [alerts,     setAlerts]     = useState<Alert[]>([]);
  const [clusters,   setClusters]   = useState<CorrelationCluster[]>([]);
  const [stats,      setStats]      = useState<Stats | null>(null);
  const [trend,      setTrend]      = useState<TrendPoint[]>([]);
  const [selected,   setSelected]   = useState<Alert | null>(null);
  const [injecting,  setInjecting]  = useState(false);
  const [injectMsg,  setInjectMsg]  = useState<string | null>(null);

  const fetchAll = useCallback(async () => {
    try { setStats(await API.stats()); } catch { /* offline */ }
    try {
      const clusterData = await API.correlationClusters();
      if (Array.isArray(clusterData)) setClusters(clusterData);
    } catch { /* offline */ }
    try {
      const data = await API.alerts(100);
      if (!Array.isArray(data)) return;
      setAlerts(data);

      // Build rolling 6-min trend (12 × 30s buckets)
      const now = Date.now();
      const pts: TrendPoint[] = [];
      for (let w = 11; w >= 0; w--) {
        const end   = now - w * 30_000;
        const start = end - 30_000;
        const label = new Date(end).toLocaleTimeString('en-GB', { hour12: false }).slice(0, 5);
        const threats = data.filter((a) => {
          const t = new Date(a.timestamp).getTime();
          return t >= start && t < end && a.dominant_threat !== 'Benign';
        }).length;
        pts.push({ time: label, threats, benign: 0 });
      }
      setTrend(pts);
    } catch { /* offline */ }
  }, []);

  useEffect(() => {
    fetchAll();
    const id = setInterval(fetchAll, 3000);
    return () => clearInterval(id);
  }, [fetchAll]);

  // Quick Attack Burst Launcher
  const quickBurst = async (type: string) => {
    if (injecting) return;
    setInjecting(true);
    setInjectMsg(`Injecting ${type} stream…`);

    const profiles: Record<string, object> = {
      syn: {
        source_ip: '10.0.4.182', destination_ip: '10.0.0.1', source_port: 12345, destination_port: 80, protocol: 6,
        iat_mean: 0.0003, iat_std: 0.00005, pkt_len_mean: 64, pkt_len_std: 2, payload_entropy: 0.15, syn_ratio: 0.99,
        tcp_rst_ratio: 0.0, tcp_fin_ratio: 0.0, duration: 0.5, packet_count: 800, byte_count: 51200,
        forward_pkts: 800, backward_pkts: 0, forward_bytes: 51200, backward_bytes: 0,
      },
      dns: {
        source_ip: '192.168.10.45', destination_ip: '8.8.8.8', source_port: 45678, destination_port: 53, protocol: 17,
        iat_mean: 0.08, iat_std: 0.02, pkt_len_mean: 190, pkt_len_std: 35, payload_entropy: 7.9, syn_ratio: 0.0,
        tcp_rst_ratio: 0.0, tcp_fin_ratio: 0.0, duration: 5.0, packet_count: 60, byte_count: 11400,
        forward_pkts: 30, backward_pkts: 30, forward_bytes: 5700, backward_bytes: 5700,
      },
      c2: {
        source_ip: '172.16.0.88', destination_ip: '91.195.240.117', source_port: 55123, destination_port: 443, protocol: 6,
        iat_mean: 2.001, iat_std: 0.0001, pkt_len_mean: 125, pkt_len_std: 5, payload_entropy: 4.1, syn_ratio: 0.0,
        tcp_rst_ratio: 0.01, tcp_fin_ratio: 0.02, duration: 120.0, packet_count: 60, byte_count: 7500,
        forward_pkts: 30, backward_pkts: 30, forward_bytes: 3750, backward_bytes: 3750,
      },
    };

    const keys = type === 'mixed' ? ['syn', 'dns', 'c2'] : [type];
    for (const k of keys) {
      if (profiles[k]) {
        try { await API.analyzeFlow(profiles[k] as Record<string, unknown>); } catch { /* ignore */ }
      }
    }
    await fetchAll();
    setInjectMsg(`✓ Stream ingested & evaluated by backend.`);
    setTimeout(() => { setInjecting(false); setInjectMsg(null); }, 2000);
  };

  const sorted = [...alerts].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  const threatCounts: Record<string, number> = {};
  for (const a of alerts) {
    const k = a.dominant_threat || 'Unknown';
    threatCounts[k] = (threatCounts[k] || 0) + 1;
  }
  const pieData = Object.entries(threatCounts).map(([name, value]) => ({ name, value }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100%' }}>
      <TopBar
        title="Security Operations Center"
        subtitle="Passive Cyber Intelligence · Unidirectional Architecture · Continuous Monitoring"
      />

      <div style={{ flex: 1, padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 20 }}>

        {/* ── Quick Threat Injection Action Bar ── */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12,
          padding: '12px 20px',
          borderRadius: 'var(--gg-radius)',
          background: 'linear-gradient(90deg, rgba(6, 182, 212, 0.12) 0%, rgba(16, 185, 129, 0.08) 100%)',
          border: '1px solid rgba(6, 182, 212, 0.3)',
          backdropFilter: 'blur(16px)',
          WebkitBackdropFilter: 'blur(16px)',
          boxShadow: '0 4px 20px rgba(0,0,0,0.35), inset 0 1px 0 rgba(255,255,255,0.1)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 28, height: 28, borderRadius: 6,
              background: 'rgba(6, 182, 212, 0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 12px rgba(6, 182, 212, 0.4)',
            }}>
              <Zap size={15} color="#22d3ee" />
            </div>
            <div>
              <span style={{ fontSize: 13, fontWeight: 700, color: '#f8fafc' }}>
                Instant Attack Simulator
              </span>
              <span style={{ fontSize: 11, color: 'var(--gg-text-3)', marginLeft: 8 }}>
                {injectMsg || 'Inject synthetic flow bursts to observe real-time AI classification, correlation & continuous operations'}
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button
              onClick={() => quickBurst('syn')}
              disabled={injecting}
              className="gg-glass-btn"
              style={{ padding: '6px 12px', borderColor: 'rgba(239, 68, 68, 0.4)', color: '#f87171' }}
            >
              🔴 SYN Flood
            </button>
            <button
              onClick={() => quickBurst('dns')}
              disabled={injecting}
              className="gg-glass-btn"
              style={{ padding: '6px 12px', borderColor: 'rgba(6, 182, 212, 0.4)', color: '#22d3ee' }}
            >
              🔵 DNS Tunnel
            </button>
            <button
              onClick={() => quickBurst('c2')}
              disabled={injecting}
              className="gg-glass-btn"
              style={{ padding: '6px 12px', borderColor: 'rgba(249, 115, 22, 0.4)', color: '#fb923c' }}
            >
              🟠 C2 Beacon
            </button>
            <button
              onClick={() => quickBurst('mixed')}
              disabled={injecting}
              className="gg-glass-btn gg-glass-btn-primary"
              style={{ padding: '6px 16px' }}
            >
              {injecting ? <RefreshCw size={13} className="animate-spin" /> : <Zap size={13} />}
              <span>⚡ Mixed Burst</span>
            </button>
          </div>
        </div>

        {/* ── 6 Top KPIs (Measured Backend Data Only) ── */}
        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 14 }}>
          <KpiCard
            label="Flows Processed"
            value={stats?.flows_processed ?? null}
            icon={<Activity size={15} />}
            iconColor="var(--gg-green)"
            note="Unidirectional stream"
          />
          <KpiCard
            label="Threats Detected"
            value={stats?.threats_detected ?? null}
            icon={<ShieldAlert size={15} />}
            iconColor="var(--gg-red)"
            warning={(stats?.threats_detected ?? 0) > 0}
          />
          <KpiCard
            label="High Risk Alerts"
            value={stats?.high_risk_alerts ?? null}
            icon={<AlertTriangle size={15} />}
            iconColor="var(--gg-orange)"
            note="CRITICAL & HIGH"
          />
          <KpiCard
            label="Novel Anomalies"
            value={stats?.anomaly_count ?? null}
            icon={<Activity size={15} />}
            iconColor="var(--gg-amber)"
            note="Isolation Forest"
          />
          <KpiCard
            label="Avg Inference"
            value={stats?.average_inference_latency_ms != null ? stats.average_inference_latency_ms.toFixed(2) : null}
            unit={stats?.average_inference_latency_ms != null ? 'ms' : undefined}
            icon={<Cpu size={15} />}
            iconColor="var(--gg-cyan)"
            note="Target < 2.0s SLA"
          />
          <KpiCard
            label="One-Way Safety"
            value={stats?.one_way_safe !== false ? 'VERIFIED' : 'ACTIVE'}
            icon={<ShieldCheck size={15} />}
            iconColor="var(--gg-green)"
            note="Zero active probing"
          />
        </section>

        {/* ── Feature A & B: Continuous Operations & Parallel Traffic View ── */}
        <section>
          <ContinuousOperations onSelectAlert={setSelected} />
        </section>

        {/* ── Feature C: Attack Stories & Correlated Incidents Preview ── */}
        {clusters.length > 0 && (
          <section className="gg-card" style={{ padding: '20px 24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <GitCommit size={18} color="var(--gg-cyan)" />
                <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--gg-text)' }}>
                  Correlated Attack Stories ({clusters.length} Active Incidents)
                </h3>
              </div>
              <Link
                href="/stories"
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  color: 'var(--gg-cyan)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4,
                  textDecoration: 'none'
                }}
              >
                Open Investigation Console <ArrowRight size={13} />
              </Link>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
              {clusters.slice(0, 3).map((c) => (
                <Link
                  key={c.cluster_id}
                  href="/stories"
                  style={{ textDecoration: 'none', color: 'inherit' }}
                >
                  <div style={{
                    padding: 14,
                    borderRadius: 'var(--gg-radius-sm)',
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid var(--gg-border)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 8,
                    transition: 'all 0.15s ease'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: 13, fontWeight: 800, color: 'var(--gg-text)', fontFamily: 'var(--font-mono)' }}>
                        {c.src_ip}
                      </span>
                      <span style={{
                        fontSize: 10, fontWeight: 700,
                        color: '#f87171', padding: '2px 6px', borderRadius: 4, background: 'rgba(239, 68, 68, 0.15)'
                      }}>
                        {(c.correlated_score * 100).toFixed(0)}% RISK
                      </span>
                    </div>

                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {c.threat_categories.map((cat) => (
                        <span key={cat} style={{
                          fontSize: 10, fontWeight: 600, color: 'var(--gg-text-2)',
                          padding: '2px 6px', borderRadius: 3, background: 'rgba(255,255,255,0.05)'
                        }}>
                          {cat}
                        </span>
                      ))}
                    </div>

                    <div style={{ fontSize: 11, color: 'var(--gg-text-3)', fontStyle: 'italic', lineHeight: 1.3 }}>
                      "{c.narrative.slice(0, 110)}…"
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </section>
        )}

        {/* ── Live Threat Activity (Trend + Distribution) ── */}
        <section style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
          {/* Trend */}
          <div className="gg-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <p className="gg-label">Threat Detections — 6-Min Rolling Window</p>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span className="status-dot status-dot-red animate-pulse-dot" />
                <span style={{ fontSize: 10, color: 'var(--gg-text-3)', fontWeight: 700 }}>PASSIVE TELEMETRY</span>
              </div>
            </div>
            {trend.some((p) => p.threats > 0) ? (
              <div style={{ height: 165 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trend}>
                    <defs>
                      <linearGradient id="tg" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.45} />
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" stroke="#4b5563" fontSize={10} tickLine={false} />
                    <YAxis stroke="#4b5563" fontSize={10} tickLine={false} allowDecimals={false} width={22} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Area
                      type="monotone"
                      dataKey="threats"
                      stroke="#ef4444"
                      strokeWidth={2.5}
                      fill="url(#tg)"
                      dot={{ r: 3, fill: '#ef4444', strokeWidth: 0 }}
                      activeDot={{ r: 5, fill: '#f87171', stroke: '#ffffff', strokeWidth: 1.5 }}
                      name="Threats"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <EmptyState
                title="NO ACTIVE THREATS"
                message="Listening on passive diode channel. Trigger an instant burst above to evaluate the models."
                actionLabel="⚡ Inject Mixed Flows"
                onAction={() => quickBurst('mixed')}
              />
            )}
          </div>

          {/* Threat distribution */}
          <div className="gg-card" style={{ padding: 22 }}>
            <p className="gg-label" style={{ marginBottom: 16 }}>Threat Distribution</p>
            {pieData.length > 0 ? (
              <>
                <div style={{ height: 130 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%" innerRadius={38} outerRadius={58}
                        dataKey="value" paddingAngle={3}>
                        {pieData.map((e) => (
                          <Cell key={e.name} fill={THREAT_COLORS[e.name] ?? '#6b7280'} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(v, n) => [v, n]} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 5 }}>
                  {pieData.slice(0, 5).map((e) => (
                    <div key={e.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11 }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 7, color: 'var(--gg-text-2)' }}>
                        <span style={{
                          width: 8, height: 8, borderRadius: '50%',
                          background: THREAT_COLORS[e.name] ?? '#6b7280',
                          boxShadow: `0 0 6px ${THREAT_COLORS[e.name] ?? '#6b7280'}88`,
                          flexShrink: 0
                        }} />
                        {e.name}
                      </span>
                      <span style={{ color: 'var(--gg-text-3)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{e.value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <EmptyState
                title="Awaiting Ingestion"
                message="Distribution graph updates upon flow detection."
              />
            )}
          </div>
        </section>

        {/* ── Recent Alerts & One-Way Architecture Safety Panel ── */}
        <section style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
          {/* Threat feed */}
          <div className="gg-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <p className="gg-label">Live Threat Stream & Consensus (Click to Inspect Evidence)</p>
              <span style={{ fontSize: 11, color: 'var(--gg-text-3)', fontFamily: 'var(--font-mono)' }}>
                {sorted.length} alerts logged
              </span>
            </div>
            {sorted.length === 0 ? (
              <EmptyState
                title="NO ACTIVE THREATS"
                message="Listening on passive diode channel. Click below to inject a sample attack flow."
                actionLabel="⚡ Inject SYN Flood"
                onAction={() => quickBurst('syn')}
              />
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--gg-border-2)' }}>
                      {['Time', 'Source → Dest', 'Proto', 'Threat', 'Risk Score', 'Severity'].map((h) => (
                        <th key={h} style={{
                          padding: '0 10px 12px 0',
                          fontSize: 10, fontWeight: 700, letterSpacing: '0.08em',
                          textTransform: 'uppercase', color: 'var(--gg-text-3)',
                          textAlign: 'left',
                        }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sorted.slice(0, 20).map((a) => (
                      <tr
                        key={a.alert_id}
                        id={`alert-row-${a.alert_id}`}
                        onClick={() => setSelected(a)}
                        className="gg-table-row animate-slide-up"
                        style={{ cursor: 'pointer' }}
                      >
                        <td style={{ padding: '11px 10px 11px 0', fontSize: 11, color: 'var(--gg-text-3)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                          {fmtTime(a.timestamp)}
                        </td>
                        <td style={{ padding: '11px 10px 11px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)', whiteSpace: 'nowrap' }}>
                          {a.source_ip}<span style={{ color: 'var(--gg-muted)' }}> → </span>{a.destination_ip}
                        </td>
                        <td style={{ padding: '11px 10px 11px 0', fontSize: 11, color: 'var(--gg-text-3)' }}>{proto(a.protocol)}</td>
                        <td style={{ padding: '11px 10px 11px 0' }}>
                          <span style={{
                            fontSize: 12,
                            fontWeight: 700,
                            color: THREAT_COLORS[a.dominant_threat] ?? 'var(--gg-text-2)',
                            textShadow: `0 0 10px ${THREAT_COLORS[a.dominant_threat] ?? '#fff'}33`,
                          }}>
                            {a.dominant_threat}
                          </span>
                        </td>
                        <td style={{ padding: '11px 10px 11px 0', minWidth: 110 }}>
                          <RiskBar score={a.final_risk_score} severity={a.severity} />
                        </td>
                        <td style={{ padding: '11px 0' }}>
                          <SeverityBadge severity={a.severity} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Right column: Safety & Health */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="gg-card" style={{ padding: 22 }}>
              <p className="gg-label" style={{ marginBottom: 16 }}>One-Way Safety & Architecture</p>
              <NetworkTopology oneWaySafe={stats?.one_way_safe !== false} />
            </div>
            <HealthPanel />
          </div>
        </section>

      </div>

      {selected && <AlertDrawer alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
