'use client';

import { useEffect, useState, useCallback } from 'react';
import { API } from '../lib/api';
import type { Alert } from '../lib/types';
import { ShieldCheck, ShieldAlert, Activity, CheckCircle2, AlertOctagon } from 'lucide-react';

function getServiceLabel(flow: Alert): string {
  const port = flow.destination_port;
  const proto = flow.protocol === 6 ? 'TCP' : flow.protocol === 17 ? 'UDP' : flow.protocol === 1 ? 'ICMP' : '';
  if (port === 443) return `Observed HTTPS Traffic (${proto}/443)`;
  if (port === 80) return `Observed HTTP Traffic (${proto}/80)`;
  if (port === 53) return `Observed DNS Traffic (${proto}/53)`;
  if (port === 22) return `Observed SSH Traffic (${proto}/22)`;
  if (port === 123) return `Observed NTP Traffic (${proto}/123)`;
  if (port > 0) return `Observed Flow (${proto}/${port})`;
  return 'Observed Flow';
}

function fmtTime(iso: string) {
  try {
    return new Date(iso).toLocaleTimeString('en-GB', { hour12: false });
  } catch {
    return iso;
  }
}

export function ContinuousOperations({ onSelectAlert }: { onSelectAlert?: (alert: Alert) => void }) {
  const [flows, setFlows] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  const loadFlows = useCallback(async () => {
    try {
      const data = await API.flows(50);
      if (Array.isArray(data)) {
        setFlows(data);
      }
    } catch {
      // offline / passive mode
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadFlows();
    const interval = setInterval(loadFlows, 3000);
    return () => clearInterval(interval);
  }, [loadFlows]);

  // Separate into Normal vs Suspicious
  const normalFlows = flows.filter(
    (f) => (f.dominant_threat || f.threat_class || f.prediction) === 'Benign' || f.severity === 'BENIGN' || f.severity === 'LOW'
  );
  const threatFlows = flows.filter(
    (f) => (f.dominant_threat || f.threat_class || f.prediction) !== 'Benign' && f.severity !== 'BENIGN' && f.severity !== 'LOW'
  );

  return (
    <div className="gg-card" style={{ padding: '22px 24px', display: 'flex', flexDirection: 'column', gap: 18 }}>
      
      {/* ── Section Title & Principle ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
            <div style={{
              width: 28, height: 28, borderRadius: 6,
              background: 'rgba(16, 185, 129, 0.15)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              display: 'flex', alignItems: 'center', justifyContent: 'center'
            }}>
              <Activity size={15} color="var(--gg-green)" />
            </div>
            <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--gg-text)' }}>
              Continuous Operations & Parallel Traffic Monitoring
            </h3>
          </div>
          <p style={{ fontSize: 11, color: 'var(--gg-text-3)', lineHeight: 1.4 }}>
            Suspicious activity detected; GeoGuards does not actively interfere with traffic.
            Benign and threat flows continue processing concurrently without blocking or degradation.
          </p>
        </div>

        {/* Operational Mode Badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <div style={{
            padding: '5px 12px',
            borderRadius: 6,
            background: 'rgba(16, 185, 129, 0.08)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            display: 'flex', alignItems: 'center', gap: 6,
            fontSize: 11, fontWeight: 700, color: '#34d399',
            fontFamily: 'var(--font-mono)'
          }}>
            <span className="status-dot status-dot-green" />
            PASSIVE MONITORING: ACTIVE
          </div>

          <div style={{
            padding: '5px 12px',
            borderRadius: 6,
            background: 'rgba(56, 189, 248, 0.08)',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            display: 'flex', alignItems: 'center', gap: 6,
            fontSize: 11, fontWeight: 700, color: '#38bdf8',
            fontFamily: 'var(--font-mono)'
          }}>
            <ShieldCheck size={13} color="#38bdf8" />
            NETWORK INTERVENTION: NONE
          </div>
        </div>
      </div>

      {/* ── Coexistence Panels: Normal vs Threat in Parallel ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        
        {/* Normal Observed Activity */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.02)',
          border: '1px solid rgba(16, 185, 129, 0.2)',
          borderRadius: 'var(--gg-radius-sm)',
          padding: 14,
          display: 'flex', flexDirection: 'column', gap: 10
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{
              fontSize: 11, fontWeight: 800, color: '#34d399',
              letterSpacing: '0.06em', textTransform: 'uppercase',
              display: 'flex', alignItems: 'center', gap: 6
            }}>
              <CheckCircle2 size={13} />
              Normal Observed Activity
            </span>
            <span style={{ fontSize: 10, color: 'var(--gg-text-3)', fontFamily: 'var(--font-mono)' }}>
              {normalFlows.length} Active Flows
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 180, overflowY: 'auto' }}>
            {normalFlows.length === 0 ? (
              <p style={{ fontSize: 11, color: 'var(--gg-text-3)', fontStyle: 'italic', padding: '8px 0' }}>
                No normal flows in current buffer.
              </p>
            ) : (
              normalFlows.slice(0, 10).map((f, i) => (
                <div key={f.alert_id || i} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '6px 10px',
                  borderRadius: 5,
                  background: 'rgba(16, 185, 129, 0.04)',
                  border: '1px solid rgba(16, 185, 129, 0.1)',
                  fontSize: 11,
                  fontFamily: 'var(--font-mono)'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#34d399', flexShrink: 0 }} />
                    <span style={{ color: 'var(--gg-text-2)' }}>{getServiceLabel(f)}</span>
                    <span style={{ color: 'var(--gg-text-3)', fontSize: 10 }}>({f.source_ip} → {f.destination_ip})</span>
                  </div>
                  <span style={{
                    fontSize: 10, fontWeight: 700, color: '#34d399',
                    padding: '2px 6px', borderRadius: 4, background: 'rgba(16, 185, 129, 0.15)'
                  }}>
                    ACTIVE
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Threat Activity */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.02)',
          border: '1px solid rgba(239, 68, 68, 0.2)',
          borderRadius: 'var(--gg-radius-sm)',
          padding: 14,
          display: 'flex', flexDirection: 'column', gap: 10
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{
              fontSize: 11, fontWeight: 800, color: '#f87171',
              letterSpacing: '0.06em', textTransform: 'uppercase',
              display: 'flex', alignItems: 'center', gap: 6
            }}>
              <ShieldAlert size={13} />
              Threat Activity (Non-Blocking Observation)
            </span>
            <span style={{ fontSize: 10, color: 'var(--gg-text-3)', fontFamily: 'var(--font-mono)' }}>
              {threatFlows.length} Flagged Flows
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 180, overflowY: 'auto' }}>
            {threatFlows.length === 0 ? (
              <p style={{ fontSize: 11, color: 'var(--gg-text-3)', fontStyle: 'italic', padding: '8px 0' }}>
                No active threat patterns detected.
              </p>
            ) : (
              threatFlows.slice(0, 10).map((f, i) => (
                <div
                  key={f.alert_id || i}
                  onClick={() => onSelectAlert?.(f)}
                  style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '6px 10px',
                    borderRadius: 5,
                    background: 'rgba(239, 68, 68, 0.04)',
                    border: '1px solid rgba(239, 68, 68, 0.15)',
                    fontSize: 11,
                    fontFamily: 'var(--font-mono)',
                    cursor: onSelectAlert ? 'pointer' : 'default'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444', flexShrink: 0 }} />
                    <span style={{ color: '#f87171', fontWeight: 600 }}>{f.dominant_threat || f.threat_class}</span>
                    <span style={{ color: 'var(--gg-text-3)', fontSize: 10 }}>({f.source_ip} → {f.destination_ip})</span>
                  </div>
                  <span style={{
                    fontSize: 10, fontWeight: 700, color: '#ef4444',
                    padding: '2px 6px', borderRadius: 4, background: 'rgba(239, 68, 68, 0.15)'
                  }}>
                    DETECTED
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* ── Parallel Sequential Flow Tree ── */}
      <div style={{
        background: 'rgba(0, 0, 0, 0.25)',
        border: '1px solid var(--gg-border)',
        borderRadius: 'var(--gg-radius-sm)',
        padding: '12px 16px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <span className="gg-label">Observed Parallel Traffic Stream (Sequential Ingest)</span>
          <span style={{ fontSize: 10, color: 'var(--gg-text-3)' }}>
            Both normal and suspicious flows are evaluated without pipeline interruption
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          {flows.slice(0, 6).map((f, idx) => {
            const isThreat = (f.dominant_threat || f.threat_class || f.prediction) !== 'Benign' && f.severity !== 'BENIGN' && f.severity !== 'LOW';
            const isLast = idx === Math.min(5, flows.length - 1);
            return (
              <div key={f.alert_id || idx} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: 'var(--gg-text-3)' }}>{isLast ? '└──' : '├──'}</span>
                <span style={{
                  color: isThreat ? '#f87171' : '#34d399',
                  fontWeight: isThreat ? 700 : 500,
                  display: 'flex', alignItems: 'center', gap: 6
                }}>
                  {isThreat ? '🔴 Suspicious Flow:' : '🟢 Normal Flow:'} {isThreat ? (f.dominant_threat || f.threat_class) : getServiceLabel(f)}
                </span>
                <span style={{ color: 'var(--gg-text-3)', fontSize: 10 }}>
                  ({f.source_ip}:{f.source_port} → {f.destination_ip}:{f.destination_port}) · {fmtTime(f.timestamp)}
                </span>
                <span style={{
                  marginLeft: 'auto',
                  fontSize: 10,
                  color: isThreat ? '#ef4444' : '#34d399',
                  fontWeight: 600
                }}>
                  {isThreat ? 'ALERT EMITTED · MONITORED' : 'ACTIVE MONITORED'}
                </span>
              </div>
            );
          })}
          {flows.length === 0 && (
            <div style={{ color: 'var(--gg-text-3)', fontStyle: 'italic' }}>
              No flows currently observed.
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
