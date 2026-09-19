'use client';

import { X, Info, ShieldAlert, AlertTriangle, CheckCircle2 } from 'lucide-react';
import type { Alert, StructuredEvidence } from '../lib/types';
import { SeverityBadge, RiskBar } from './SeverityBadge';

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

function proto(n: number) {
  return n === 6 ? 'TCP' : n === 17 ? 'UDP' : n === 1 ? 'ICMP' : n ? String(n) : '—';
}
function pct(v: number) { return `${(v * 100).toFixed(1)}%`; }

export function AlertDrawer({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const threatColor = THREAT_COLORS[alert.dominant_threat] ?? 'var(--gg-text-2)';
  const sources = alert.detection_sources || [];

  // Determine which detection pillars contributed
  const hasSupervised = sources.some(s => s.toLowerCase().includes('supervised') || s.toLowerCase().includes('classifier'));
  const hasAnomaly = alert.is_anomaly || sources.some(s => s.toLowerCase().includes('anomaly'));
  const hasBehaviour = (alert.behaviour_score ?? 0) > 0 || sources.some(s => s.toLowerCase().includes('behaviour'));
  const hasSpecialized = sources.some(s => 
    s.includes('ddos') || s.includes('c2') || s.includes('dns') || s.includes('recon') || s.includes('exfil') || s.includes('encrypted')
  );

  return (
    <div className="gg-modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="gg-modal-panel" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 660 }}>

        {/* ── Title / Header: "Why did GeoGuards alert?" ── */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 18 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{
                fontSize: 11, fontWeight: 800,
                color: 'var(--gg-cyan)', letterSpacing: '0.08em', textTransform: 'uppercase'
              }}>
                Forensic Investigation
              </span>
              <span style={{ fontSize: 11, color: 'var(--gg-text-3)' }}>·</span>
              <span style={{ fontSize: 11, color: 'var(--gg-text-3)', fontFamily: 'var(--font-mono)' }}>
                {alert.alert_id}
              </span>
            </div>

            <h2 style={{ fontSize: 20, fontWeight: 800, color: 'var(--gg-text)', letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: 10 }}>
              Why did GeoGuards alert?
            </h2>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', marginTop: 6 }}>
              <span style={{
                fontSize: 12, fontWeight: 700, color: threatColor,
                display: 'flex', alignItems: 'center', gap: 5
              }}>
                <ShieldAlert size={14} color={threatColor} />
                {alert.dominant_threat || alert.threat_class}
              </span>
              <SeverityBadge severity={alert.severity} />
              {alert.analysis_mode && (
                <span style={{
                  fontSize: 10,
                  padding: '2px 8px',
                  borderRadius: 12,
                  background: alert.analysis_mode.includes('pcap')
                    ? 'rgba(168,85,247,0.12)'
                    : alert.analysis_mode.includes('demo')
                    ? 'rgba(245,158,11,0.12)'
                    : 'rgba(6,182,212,0.12)',
                  border: `1px solid ${
                    alert.analysis_mode.includes('pcap')
                      ? 'rgba(168,85,247,0.4)'
                      : alert.analysis_mode.includes('demo')
                      ? 'rgba(245,158,11,0.4)'
                      : 'rgba(6,182,212,0.4)'
                  }`,
                  color: alert.analysis_mode.includes('pcap')
                    ? '#c084fc'
                    : alert.analysis_mode.includes('demo')
                    ? '#fbbf24'
                    : '#22d3ee',
                  textTransform: 'uppercase',
                  fontWeight: 700
                }}>
                  Source: {
                    alert.analysis_mode.includes('pcap') ? 'PCAP Replay' :
                    alert.analysis_mode.includes('demo') ? 'Demo Simulation' :
                    'Live Ingest'
                  }
                </span>
              )}
              <span style={{
                fontSize: 10,
                padding: '2px 8px',
                borderRadius: 12,
                background: 'rgba(16,185,129,0.1)',
                border: '1px solid rgba(16,185,129,0.3)',
                color: '#34d399',
                fontWeight: 600
              }}>
                ✓ One-Way Safe
              </span>
            </div>
          </div>

          <button
            id="alert-drawer-close"
            onClick={onClose}
            style={{
              color: 'var(--gg-text-3)',
              cursor: 'pointer',
              background: 'rgba(255,255,255,0.05)',
              border: '1px solid var(--gg-border)',
              borderRadius: 6,
              padding: 6,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease',
            }}
            aria-label="Close alert detail"
          >
            <X size={16} />
          </button>
        </div>

        {/* ── Key Confidence & Risk Metrics ── */}
        <div style={{
          display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16
        }}>
          <div style={{
            padding: 14, borderRadius: 'var(--gg-radius-sm)',
            background: 'rgba(255, 255, 255, 0.025)', border: '1px solid var(--gg-border)'
          }}>
            <span className="gg-label">Confidence</span>
            <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--gg-cyan)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>
              {pct(alert.confidence)}
            </div>
            <span style={{ fontSize: 10, color: 'var(--gg-text-3)' }}>
              Primary signature probability
            </span>
          </div>

          <div style={{
            padding: 14, borderRadius: 'var(--gg-radius-sm)',
            background: 'rgba(255, 255, 255, 0.025)', border: '1px solid var(--gg-border)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="gg-label">Fused Risk Score</span>
              <span style={{ fontSize: 14, fontWeight: 800, color: threatColor, fontFamily: 'var(--font-mono)' }}>
                {Math.round((alert.final_risk_score ?? alert.risk_score ?? 0) * 100)}/100
              </span>
            </div>
            <div style={{ marginTop: 8 }}>
              <RiskBar score={alert.final_risk_score ?? alert.risk_score ?? 0} severity={alert.severity} />
            </div>
          </div>
        </div>

        {/* ── Feature E: Novel Behaviour (Isolation Forest) ── */}
        <div style={{
          padding: 14,
          borderRadius: 'var(--gg-radius-sm)',
          background: alert.is_anomaly ? 'rgba(245, 158, 11, 0.06)' : 'rgba(16, 185, 129, 0.04)',
          border: `1px solid ${alert.is_anomaly ? 'rgba(245, 158, 11, 0.3)' : 'rgba(16, 185, 129, 0.2)'}`,
          marginBottom: 16,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span style={{
              fontSize: 11, fontWeight: 800,
              color: alert.is_anomaly ? '#fbbf24' : '#34d399',
              letterSpacing: '0.06em', textTransform: 'uppercase',
              display: 'flex', alignItems: 'center', gap: 6
            }}>
              {alert.is_anomaly ? <AlertTriangle size={14} /> : <CheckCircle2 size={14} />}
              {alert.is_anomaly ? 'NOVEL BEHAVIOUR DETECTED' : 'NO NOVEL BEHAVIOUR DETECTED'}
            </span>
            <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>
              Score: <strong>{(alert.anomaly_score * 100).toFixed(1)}%</strong> (Threshold: 55.0%)
            </span>
          </div>
          <p style={{ fontSize: 11, color: 'var(--gg-text-2)', lineHeight: 1.4, margin: 0 }}>
            {alert.is_anomaly
              ? 'Traffic differs significantly from the learned benign baseline (fitted on clean CIC-IDS2017 Monday/Tuesday). Note: Statistical anomaly flags unusual flow distributions and is not an inherent confirmation of malicious intent.'
              : 'Flow metadata characteristics fall within the learned benign statistical baseline.'}
          </p>
        </div>

        {/* ── Detection Source Attribution ── */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.02)',
          border: '1px solid var(--gg-border)',
          borderRadius: 'var(--gg-radius-sm)',
          padding: 14,
          marginBottom: 16,
        }}>
          <p className="gg-label" style={{ marginBottom: 10 }}>Detection Pillar Attribution (Backend Consensus)</p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
            {[
              { name: 'Supervised ML', active: hasSupervised, score: pct(alert.confidence), color: '#22d3ee' },
              { name: 'Anomaly Det.', active: hasAnomaly, score: pct(alert.anomaly_score), color: '#fbbf24' },
              { name: 'Behaviour', active: hasBehaviour, score: pct(alert.behaviour_score), color: '#fb923c' },
              { name: 'Specialized', active: hasSpecialized, score: hasSpecialized ? 'FLAGGED' : 'CLEAN', color: '#a855f7' },
            ].map(({ name, active, score, color }) => (
              <div key={name} style={{
                padding: '8px 10px',
                borderRadius: 6,
                background: active ? `${color}12` : 'rgba(255,255,255,0.02)',
                border: `1px solid ${active ? `${color}44` : 'rgba(255,255,255,0.06)'}`,
                textAlign: 'center'
              }}>
                <div style={{ fontSize: 10, color: active ? color : 'var(--gg-text-3)', fontWeight: 700 }}>
                  {name}
                </div>
                <div style={{
                  fontSize: 11,
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  color: active ? 'var(--gg-text)' : 'var(--gg-text-3)',
                  marginTop: 2
                }}>
                  {active ? `✓ ${score}` : '— None'}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Structured Measurable Evidence ── */}
        <div style={{ marginBottom: 16 }}>
          <p className="gg-label" style={{ marginBottom: 8 }}>Measured Flow Evidence & Signal Interpretation</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 180, overflowY: 'auto' }}>
            {alert.evidence && alert.evidence.length > 0 ? (
              alert.evidence.map((ev, i) => {
                if (typeof ev === 'object' && ev !== null && 'feature' in ev) {
                  const structEv = ev as StructuredEvidence;
                  return (
                    <div key={i} style={{
                      display: 'flex', flexDirection: 'column', gap: 2,
                      padding: '8px 10px',
                      borderRadius: 6,
                      background: 'rgba(16, 185, 129, 0.04)',
                      border: '1px solid rgba(16, 185, 129, 0.15)',
                      fontSize: 11,
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ color: '#34d399', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                          {structEv.feature}
                        </span>
                        <span style={{ color: 'var(--gg-text-2)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                          Observed Value: {String(structEv.observed_value)}
                        </span>
                      </div>
                      <span style={{ color: 'var(--gg-text-3)' }}>{structEv.interpretation}</span>
                    </div>
                  );
                }
                return (
                  <div key={i} style={{
                    display: 'flex', gap: 8, fontSize: 11, color: 'var(--gg-text-2)',
                    padding: '6px 10px',
                    borderRadius: 6,
                    background: 'rgba(16, 185, 129, 0.04)',
                    border: '1px solid rgba(16, 185, 129, 0.15)',
                  }}>
                    <span style={{ color: '#34d399', flexShrink: 0 }}>✓</span>
                    <span>{String(ev)}</span>
                  </div>
                );
              })
            ) : (
              <p style={{ fontSize: 11, color: 'var(--gg-text-3)', fontStyle: 'italic' }}>
                No explicit structured evidence items returned.
              </p>
            )}
          </div>
        </div>

        {/* ── Observed 5-Tuple Metadata ── */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.025)',
          border: '1px solid var(--gg-border)',
          borderRadius: 'var(--gg-radius-sm)',
          padding: 12,
          marginBottom: 16,
        }}>
          <p className="gg-label" style={{ marginBottom: 8 }}>Observed Flow Metadata</p>
          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 16px',
            fontSize: 11, fontFamily: 'var(--font-mono)'
          }}>
            <div>
              <span style={{ color: 'var(--gg-text-3)' }}>Source: </span>
              <span style={{ color: 'var(--gg-text)' }}>{alert.source_ip}:{alert.source_port}</span>
            </div>
            <div>
              <span style={{ color: 'var(--gg-text-3)' }}>Destination: </span>
              <span style={{ color: 'var(--gg-text)' }}>{alert.destination_ip}:{alert.destination_port}</span>
            </div>
            <div>
              <span style={{ color: 'var(--gg-text-3)' }}>Protocol: </span>
              <span style={{ color: 'var(--gg-text)' }}>{proto(alert.protocol)}</span>
            </div>
            {alert.inference_latency_ms != null && (
              <div>
                <span style={{ color: 'var(--gg-text-3)' }}>Measured Latency: </span>
                <span style={{ color: 'var(--gg-green)' }}>{alert.inference_latency_ms.toFixed(3)} ms</span>
              </div>
            )}
          </div>
        </div>

        {/* ── Analyst Forensic Narrative ── */}
        {alert.explanation && (
          <div style={{
            background: 'rgba(6, 182, 212, 0.05)',
            border: '1px solid rgba(6, 182, 212, 0.2)',
            borderRadius: 'var(--gg-radius-sm)',
            padding: 12,
          }}>
            <p className="gg-label" style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4, color: '#22d3ee' }}>
              <Info size={12} />
              Forensic Rationale
            </p>
            <p style={{ fontSize: 11, color: 'var(--gg-text-2)', lineHeight: 1.4, margin: 0 }}>
              {alert.explanation}
            </p>
          </div>
        )}

      </div>
    </div>
  );
}
