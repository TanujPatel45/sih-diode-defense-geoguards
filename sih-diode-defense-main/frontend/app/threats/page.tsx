'use client';

import { useCallback, useEffect, useState } from 'react';
import { API } from '../lib/api';
import type { Alert } from '../lib/types';
import { TopBar } from '../components/TopBar';
import { SeverityBadge, RiskBar } from '../components/SeverityBadge';
import { AlertDrawer } from '../components/AlertDrawer';
import { EmptyState, LoadingState } from '../components/EmptyState';

const SEVS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const THREAT_COLORS: Record<string, string> = {
  'SYN/UDP Flood': '#f87171',
  'DNS Tunneling': '#22d3ee',
  'C2 Beaconing':  '#fb923c',
  'Anomaly':       '#fbbf24',
  'Benign':        '#34d399',
};

function fmtTime(iso: string) {
  try { return new Date(iso).toLocaleString('en-GB', { hour12: false }); } catch { return iso; }
}
function proto(n: number) {
  return n === 6 ? 'TCP' : n === 17 ? 'UDP' : n === 1 ? 'ICMP' : String(n);
}

export default function Threats() {
  const [alerts,   setAlerts]   = useState<Alert[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [filter,   setFilter]   = useState('ALL');
  const [selected, setSelected] = useState<Alert | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await API.alerts(200);
      if (Array.isArray(data)) setAlerts(data);
    } catch { /* offline */ } finally { setLoading(false); }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  const filtered = alerts
    .filter((a) => filter === 'ALL' || a.severity === filter)
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  const counts = Object.fromEntries(SEVS.map((s) => [
    s, s === 'ALL' ? alerts.length : alerts.filter((a) => a.severity === s).length
  ]));

  const SEV_CONFIG: Record<string, { color: string; border: string; bg: string; glow: string }> = {
    ALL:      { color: '#34d399', border: 'rgba(16,185,129,0.4)', bg: 'rgba(16,185,129,0.12)', glow: 'rgba(16,185,129,0.2)' },
    CRITICAL: { color: '#f87171', border: 'rgba(239,68,68,0.4)',  bg: 'rgba(239,68,68,0.12)',  glow: 'rgba(239,68,68,0.2)' },
    HIGH:     { color: '#fb923c', border: 'rgba(249,115,22,0.4)', bg: 'rgba(249,115,22,0.12)', glow: 'rgba(249,115,22,0.2)' },
    MEDIUM:   { color: '#fbbf24', border: 'rgba(245,158,11,0.4)', bg: 'rgba(245,158,11,0.12)', glow: 'rgba(245,158,11,0.2)' },
    LOW:      { color: '#34d399', border: 'rgba(16,185,129,0.4)', bg: 'rgba(16,185,129,0.12)', glow: 'rgba(16,185,129,0.2)' },
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100%' }}>
      <TopBar title="Threats Feed" subtitle="Passive telemetry anomaly & threat analysis · Click row to inspect model consensus" />

      <div style={{ flex: 1, padding: 24 }}>
        {/* Filter chips */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
          {SEVS.map((s) => {
            const active = filter === s;
            const cfg = SEV_CONFIG[s];
            return (
              <button
                key={s}
                onClick={() => setFilter(s)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '7px 16px',
                  borderRadius: 'var(--gg-radius-sm)',
                  border: `1px solid ${active ? cfg.border : 'var(--gg-border)'}`,
                  background: active ? cfg.bg : 'rgba(255, 255, 255, 0.03)',
                  backdropFilter: 'blur(12px)',
                  WebkitBackdropFilter: 'blur(12px)',
                  boxShadow: active
                    ? `0 0 16px ${cfg.glow}, inset 0 1px 0 rgba(255,255,255,0.12)`
                    : 'inset 0 1px 0 rgba(255,255,255,0.04)',
                  color: active ? cfg.color : 'var(--gg-text-2)',
                  fontSize: 12,
                  fontWeight: active ? 700 : 500,
                  cursor: 'pointer',
                  transition: 'all 0.18s ease',
                }}
              >
                <span>{s}</span>
                <span style={{
                  fontSize: 10,
                  fontWeight: 700,
                  padding: '1px 7px',
                  borderRadius: 12,
                  background: active ? 'rgba(0,0,0,0.3)' : 'rgba(255,255,255,0.06)',
                  color: active ? cfg.color : 'var(--gg-text-3)',
                }}>
                  {counts[s]}
                </span>
              </button>
            );
          })}
        </div>

        {/* Glass Card Table */}
        <div className="gg-card" style={{ padding: '20px 24px' }}>
          {loading ? (
            <LoadingState />
          ) : filtered.length === 0 ? (
            <EmptyState
              title={filter === 'ALL' ? 'NO THREATS RECORDED' : `NO ${filter} ALERTS`}
              message={
                filter === 'ALL'
                  ? 'No threats detected. Use the Demo Lab or PCAP Analysis to generate traffic.'
                  : `No ${filter} severity alerts recorded.`
              }
            />
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--gg-border-2)' }}>
                    {['Timestamp', 'Source IP', 'Dest IP', 'Proto', 'Threat Signature', 'Classifier', 'Anomaly', 'Behaviour', 'Risk Score', 'Severity'].map((h) => (
                      <th key={h} style={{
                        padding: '0 12px 12px 0',
                        fontSize: 10,
                        fontWeight: 700,
                        letterSpacing: '0.08em',
                        textTransform: 'uppercase' as const,
                        color: 'var(--gg-text-3)',
                        textAlign: 'left' as const,
                      }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((a) => (
                    <tr
                      key={a.alert_id}
                      id={`threat-row-${a.alert_id}`}
                      onClick={() => setSelected(a)}
                      className="gg-table-row"
                    >
                      <td style={{ padding: '11px 12px 11px 0', fontSize: 11, color: 'var(--gg-text-3)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                        {fmtTime(a.timestamp)}
                      </td>
                      <td style={{ padding: '11px 12px 11px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>{a.source_ip}</td>
                      <td style={{ padding: '11px 12px 11px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>{a.destination_ip}</td>
                      <td style={{ padding: '11px 12px 11px 0', fontSize: 11, color: 'var(--gg-text-3)' }}>{proto(a.protocol)}</td>
                      <td style={{ padding: '11px 12px 11px 0' }}>
                        <span style={{
                          fontSize: 12,
                          fontWeight: 700,
                          color: THREAT_COLORS[a.dominant_threat] ?? 'var(--gg-text)',
                          textShadow: `0 0 10px ${THREAT_COLORS[a.dominant_threat] ?? '#fff'}44`,
                        }}>
                          {a.dominant_threat}
                        </span>
                      </td>
                      <td style={{ padding: '11px 12px 11px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>
                        {(a.confidence * 100).toFixed(0)}%
                      </td>
                      <td style={{ padding: '11px 12px 11px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: a.is_anomaly ? '#fbbf24' : 'var(--gg-text-3)' }}>
                        {(a.anomaly_score * 100).toFixed(0)}%
                      </td>
                      <td style={{ padding: '11px 12px 11px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>
                        {(a.behaviour_score * 100).toFixed(0)}%
                      </td>
                      <td style={{ padding: '11px 12px 11px 0', minWidth: 120 }}>
                        <RiskBar score={a.final_risk_score} severity={a.severity} />
                      </td>
                      <td style={{ padding: '11px 0' }}><SeverityBadge severity={a.severity} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {selected && <AlertDrawer alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
