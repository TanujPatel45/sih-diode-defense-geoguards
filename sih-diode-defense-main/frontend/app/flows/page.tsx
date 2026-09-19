'use client';

import { useCallback, useEffect, useState } from 'react';
import { API } from '../lib/api';
import type { Alert } from '../lib/types';
import { TopBar } from '../components/TopBar';
import { AlertDrawer } from '../components/AlertDrawer';
import { EmptyState, LoadingState } from '../components/EmptyState';

function proto(n: number) {
  return n === 6 ? 'TCP' : n === 17 ? 'UDP' : n === 1 ? 'ICMP' : String(n);
}
function fmtNum(v: number | undefined, dec = 2) {
  if (v === undefined || v === null) return '—';
  return typeof v === 'number' ? v.toFixed(dec) : String(v);
}

const COLS = [
  { key: 'timestamp',       label: 'Time' },
  { key: 'source_ip',       label: 'Src IP' },
  { key: 'destination_ip',  label: 'Dst IP' },
  { key: 'source_port',     label: 'Src Port' },
  { key: 'destination_port',label: 'Dst Port' },
  { key: 'protocol',        label: 'Proto' },
  { key: 'prediction',      label: 'Classifier' },
  { key: 'final_risk_score',label: 'Risk' },
  { key: 'severity',        label: 'Severity' },
];

const FEATURE_GROUPS = [
  { title: 'Flow Identity', keys: ['source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol'] },
  { title: 'Timing', keys: ['iat_mean', 'iat_std', 'duration'] },
  { title: 'Packet / Byte', keys: ['packet_count', 'byte_count'] },
  { title: 'Payload Metadata', keys: ['payload_entropy'] },
  { title: 'TCP Flags', keys: ['syn_ratio', 'tcp_rst_ratio', 'tcp_fin_ratio'] },
  { title: 'Packet Length', keys: ['pkt_len_mean', 'pkt_len_std'] },
];

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#22c55e',
};

export default function FlowExplorer() {
  const [flows,    setFlows]    = useState<Alert[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [detail,   setDetail]   = useState<Alert | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await API.flows(200);
      if (Array.isArray(data)) setFlows(data);
    } catch { /* offline */ } finally { setLoading(false); }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  const sorted = [...flows].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100%' }}>
      <TopBar title="Flow Explorer" subtitle="All analyzed flows including benign traffic · Click a row to inspect features" />

      <div style={{ flex: 1, padding: 24, display: 'flex', gap: 16 }}>
        {/* Flow table */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="gg-card" style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 14 }}>
              <p className="gg-label">Flow Records</p>
              <span style={{ fontSize: 11, color: 'var(--gg-muted)' }}>{flows.length} flows</span>
            </div>

            {loading ? (
              <LoadingState />
            ) : sorted.length === 0 ? (
              <EmptyState
                title="NO FLOWS RECORDED"
                message="No flows have been analyzed yet. Use the Demo Lab or PCAP Analysis to generate traffic."
              />
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--gg-border)' }}>
                      {COLS.map((c) => (
                        <th key={c.key} style={{
                          padding: '0 10px 10px 0', fontSize: 10, fontWeight: 600,
                          letterSpacing: '0.08em', textTransform: 'uppercase' as const,
                          color: 'var(--gg-muted)', textAlign: 'left' as const, whiteSpace: 'nowrap',
                        }}>{c.label}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sorted.map((f) => (
                      <tr
                        key={f.alert_id}
                        onClick={() => { setSelected(null); setDetail(f); }}
                        style={{
                          borderBottom: '1px solid rgba(31,41,55,0.4)',
                          cursor: 'pointer',
                          background: detail?.alert_id === f.alert_id ? 'var(--gg-surface-2)' : 'transparent',
                        }}
                        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--gg-surface-2)')}
                        onMouseLeave={(e) => (e.currentTarget.style.background =
                          detail?.alert_id === f.alert_id ? 'var(--gg-surface-2)' : 'transparent')}
                      >
                        <td style={{ padding: '8px 10px 8px 0', fontSize: 11, color: 'var(--gg-muted)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                          {new Date(f.timestamp).toLocaleTimeString('en-GB', { hour12: false })}
                        </td>
                        <td style={{ padding: '8px 10px 8px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>{f.source_ip}</td>
                        <td style={{ padding: '8px 10px 8px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>{f.destination_ip}</td>
                        <td style={{ padding: '8px 10px 8px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-muted)' }}>{f.source_port}</td>
                        <td style={{ padding: '8px 10px 8px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-muted)' }}>{f.destination_port}</td>
                        <td style={{ padding: '8px 10px 8px 0', fontSize: 11, color: 'var(--gg-muted)' }}>{proto(f.protocol)}</td>
                        <td style={{ padding: '8px 10px 8px 0' }}>
                          <span style={{
                            fontSize: 11, fontWeight: 600,
                            color: f.prediction === 'Benign' ? 'var(--gg-green)' :
                              f.severity === 'CRITICAL' ? '#ef4444' : 'var(--gg-amber)',
                          }}>{f.prediction}</span>
                        </td>
                        <td style={{ padding: '8px 10px 8px 0', fontSize: 11, fontFamily: 'var(--font-mono)',
                          color: SEV_COLOR[f.severity] ?? 'var(--gg-muted)' }}>
                          {(f.final_risk_score * 100).toFixed(0)}
                        </td>
                        <td style={{ padding: '8px 0', fontSize: 10, fontWeight: 600, letterSpacing: '0.06em',
                          color: SEV_COLOR[f.severity] ?? 'var(--gg-muted)' }}>
                          {f.severity}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Feature panel */}
        {detail && (
          <div className="gg-card" style={{ width: 280, flexShrink: 0, padding: 20, overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
              <p className="gg-label">Flow Features</p>
              <button onClick={() => setDetail(null)}
                style={{ background: 'none', border: 'none', color: 'var(--gg-muted)', cursor: 'pointer', fontSize: 14 }}>
                ×
              </button>
            </div>

            {/* Alert investigation button */}
            {detail.dominant_threat !== 'Benign' && (
              <button
                onClick={() => { setSelected(detail); }}
                style={{
                  width: '100%', padding: '7px 0', marginBottom: 16,
                  border: '1px solid var(--gg-border-2)', borderRadius: 6,
                  background: 'var(--gg-surface-2)',
                  color: 'var(--gg-text-2)', fontSize: 12, cursor: 'pointer',
                }}
              >
                Open Alert Investigation →
              </button>
            )}

            {FEATURE_GROUPS.map((g) => (
              <div key={g.title} style={{ marginBottom: 16 }}>
                <p className="gg-label" style={{ marginBottom: 8, color: 'var(--gg-muted)' }}>{g.title}</p>
                {g.keys.map((k) => {
                  const val = k === 'source_ip' ? detail.source_ip
                    : k === 'destination_ip' ? detail.destination_ip
                    : k === 'source_port' ? detail.source_port
                    : k === 'destination_port' ? detail.destination_port
                    : k === 'protocol' ? proto(detail.protocol)
                    : detail.features?.[k];
                  return (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0',
                      borderBottom: '1px solid rgba(31,41,55,0.3)', fontSize: 11 }}>
                      <span style={{ color: 'var(--gg-muted)' }}>{k}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>
                        {typeof val === 'number' ? fmtNum(val, k.includes('ratio') || k.includes('entropy') || k.includes('iat') ? 4 : 2)
                          : val ?? '—'}
                      </span>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        )}
      </div>

      {selected && <AlertDrawer alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
