'use client';

import { useState, useEffect, useCallback } from 'react';
import { API } from '../lib/api';
import type { CorrelationCluster, TimelineEvent, Alert } from '../lib/types';
import { TopBar } from '../components/TopBar';
import { SeverityBadge, RiskBar } from '../components/SeverityBadge';
import { EmptyState, LoadingState } from '../components/EmptyState';
import { AlertDrawer } from '../components/AlertDrawer';
import { GuidedReplayControl } from '../components/GuidedReplayControl';
import {
  GitCommit, ArrowRight, ShieldAlert, Activity, CheckCircle2,
  Clock, Server, Eye, ExternalLink, ShieldCheck, Cpu
} from 'lucide-react';

function fmtTime(iso: string) {
  try {
    return new Date(iso).toLocaleTimeString('en-GB', { hour12: false });
  } catch {
    return iso;
  }
}

function calcDuration(start: string, end: string): string {
  try {
    const diff = (new Date(end).getTime() - new Date(start).getTime()) / 1000;
    if (diff < 60) return `${Math.round(diff)}s`;
    return `${Math.round(diff / 60)}m ${Math.round(diff % 60)}s`;
  } catch {
    return '—';
  }
}

const CATEGORY_COLORS: Record<string, string> = {
  'Reconnaissance / Port Scanning': '#a855f7',
  'Botnet C2 Beaconing': '#fb923c',
  'C2 Beaconing': '#fb923c',
  'DGA Domains and DNS Tunnelling': '#22d3ee',
  'DNS Tunneling': '#22d3ee',
  'Volumetric / Protocol DDoS': '#ef4444',
  'SYN/UDP Flood': '#ef4444',
  'Data Exfiltration': '#ec4899',
  'Malware in Encrypted Sessions': '#3b82f6',
  'Anomaly': '#fbbf24',
};

export default function AttackStories() {
  const [clusters, setClusters] = useState<CorrelationCluster[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCluster, setSelectedCluster] = useState<CorrelationCluster | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  const loadClusters = useCallback(async () => {
    try {
      const data = await API.correlationClusters();
      if (Array.isArray(data)) {
        setClusters(data);
        // Refresh selected cluster reference if open
        if (selectedCluster) {
          const updated = data.find(c => c.cluster_id === selectedCluster.cluster_id);
          if (updated) setSelectedCluster(updated);
        }
      }
    } catch {
      // offline
    } finally {
      setLoading(false);
    }
  }, [selectedCluster]);

  useEffect(() => {
    loadClusters();
    const interval = setInterval(loadClusters, 4000);
    return () => clearInterval(interval);
  }, [loadClusters]);

  const getClusterSeverity = (score: number) => {
    if (score >= 0.85) return 'CRITICAL';
    if (score >= 0.65) return 'HIGH';
    if (score >= 0.40) return 'MEDIUM';
    return 'LOW';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100%' }}>
      <TopBar
        title="Attack Stories & Incident Correlation"
        subtitle="Multi-signal host and temporal aggregation · Explains the evidence behind correlated threat progressions"
      />

      <div style={{ flex: 1, padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
        
        {/* ── Top Philosophy / Passive Guarantees Banner ── */}
        <div style={{
          padding: '12px 18px',
          borderRadius: 'var(--gg-radius)',
          background: 'rgba(99, 102, 241, 0.06)',
          border: '1px solid rgba(99, 102, 241, 0.25)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12
        }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--gg-text)' }}>
              Passive Attack Progression Correlation Engine
            </div>
            <div style={{ fontSize: 11, color: 'var(--gg-text-3)', marginTop: 2 }}>
              Correlates related threat events by origin IP within sliding 15-minute observation windows without active probing or network disruption.
            </div>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <div style={{
              padding: '4px 10px', borderRadius: 4,
              background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)',
              fontSize: 10, fontWeight: 700, color: '#34d399', fontFamily: 'var(--font-mono)'
            }}>
              PASSIVE MONITORING: ACTIVE
            </div>
            <div style={{
              padding: '4px 10px', borderRadius: 4,
              background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.3)',
              fontSize: 10, fontWeight: 700, color: '#38bdf8', fontFamily: 'var(--font-mono)'
            }}>
              ACTIVE RESPONSE: NONE
            </div>
          </div>
        </div>

        {/* ── Guided Multi-Stage Attack Replay Stream Control ── */}
        <GuidedReplayControl onRefresh={loadClusters} />

        {/* ── Active Incident Clusters Grid ── */}
        {loading ? (
          <LoadingState />
        ) : clusters.length === 0 ? (
          <div className="gg-card" style={{ padding: 32 }}>
            <EmptyState
              title="NO CORRELATED INCIDENTS"
              message="No multi-flow threat chains currently correlated. As suspicious flows are detected from common sources, the backend groups them into structured Attack Stories."
            />
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: selectedCluster ? '1fr 1fr' : 'repeat(auto-fill, minmax(360px, 1fr))', gap: 16 }}>
            
            {/* Cluster Cards Column */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="gg-label">Correlated Threat Stories ({clusters.length})</span>
                <span style={{ fontSize: 11, color: 'var(--gg-muted)' }}>Click card to investigate</span>
              </div>

              {clusters.map((c) => {
                const isSelected = selectedCluster?.cluster_id === c.cluster_id;
                const sev = getClusterSeverity(c.correlated_score);
                return (
                  <div
                    key={c.cluster_id}
                    onClick={() => setSelectedCluster(c)}
                    className="gg-card"
                    style={{
                      padding: 18,
                      cursor: 'pointer',
                      border: `1px solid ${isSelected ? 'var(--gg-cyan)' : 'var(--gg-border)'}`,
                      background: isSelected ? 'rgba(6, 182, 212, 0.06)' : 'var(--gg-surface)',
                      transition: 'all 0.15s ease',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 12
                    }}
                  >
                    {/* Header */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div>
                        <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-3)', marginBottom: 2 }}>
                          {c.cluster_id}
                        </div>
                        <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--gg-text)', fontFamily: 'var(--font-mono)' }}>
                          Source: {c.src_ip}
                        </div>
                      </div>
                      <SeverityBadge severity={sev} />
                    </div>

                    {/* Attack Progression Breadcrumb */}
                    <div>
                      <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--gg-text-3)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                        Attack Progression:
                      </span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginTop: 6 }}>
                        {c.threat_categories.map((cat, idx) => {
                          const col = CATEGORY_COLORS[cat] ?? 'var(--gg-text)';
                          return (
                            <div key={cat} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              <span style={{
                                fontSize: 11,
                                fontWeight: 700,
                                color: col,
                                padding: '2px 8px',
                                borderRadius: 4,
                                background: `${col}15`,
                                border: `1px solid ${col}44`
                              }}>
                                {cat}
                              </span>
                              {idx < c.threat_categories.length - 1 && (
                                <ArrowRight size={12} color="var(--gg-text-3)" />
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Metadata & Risk Bar */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                      <div>
                        <span style={{ color: 'var(--gg-text-3)', fontSize: 10 }}>First Seen</span>
                        <div style={{ color: 'var(--gg-text-2)' }}>{fmtTime(c.first_seen)}</div>
                      </div>
                      <div>
                        <span style={{ color: 'var(--gg-text-3)', fontSize: 10 }}>Last Seen</span>
                        <div style={{ color: 'var(--gg-text-2)' }}>{fmtTime(c.last_seen)}</div>
                      </div>
                      <div>
                        <span style={{ color: 'var(--gg-text-3)', fontSize: 10 }}>Flow Events</span>
                        <div style={{ color: 'var(--gg-cyan)', fontWeight: 700 }}>{c.total_flows} flows</div>
                      </div>
                    </div>

                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, marginBottom: 4 }}>
                        <span style={{ color: 'var(--gg-text-3)' }}>Correlated Risk Score</span>
                        <span style={{ color: 'var(--gg-text)', fontWeight: 700 }}>{(c.correlated_score * 100).toFixed(0)}%</span>
                      </div>
                      <RiskBar score={c.correlated_score} severity={sev} />
                    </div>

                    {/* Narrative Snippet */}
                    <div style={{
                      fontSize: 11, color: 'var(--gg-text-2)', lineHeight: 1.4,
                      background: 'rgba(255,255,255,0.02)', padding: '8px 10px', borderRadius: 4,
                      border: '1px solid rgba(255,255,255,0.05)', fontStyle: 'italic'
                    }}>
                      "{c.narrative}"
                    </div>

                  </div>
                );
              })}
            </div>

            {/* Investigation View (Detailed Story) */}
            {selectedCluster && (
              <div className="gg-card" style={{ padding: 22, display: 'flex', flexDirection: 'column', gap: 18 }}>
                
                {/* Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <span className="gg-label">Attack Story Investigation</span>
                    <h3 style={{ fontSize: 18, fontWeight: 800, color: 'var(--gg-text)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>
                      {selectedCluster.cluster_id}
                    </h3>
                    <div style={{ fontSize: 11, color: 'var(--gg-text-3)', marginTop: 2 }}>
                      Duration: {calcDuration(selectedCluster.first_seen, selectedCluster.last_seen)} · Source IP: {selectedCluster.src_ip}
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedCluster(null)}
                    style={{
                      fontSize: 11, color: 'var(--gg-text-3)', cursor: 'pointer',
                      background: 'rgba(255,255,255,0.05)', border: '1px solid var(--gg-border)',
                      padding: '4px 10px', borderRadius: 4
                    }}
                  >
                    Close Detail
                  </button>
                </div>

                {/* 1. Incident Summary */}
                <div style={{
                  padding: 14, borderRadius: 'var(--gg-radius-sm)',
                  background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--gg-border)',
                  display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, fontSize: 11, fontFamily: 'var(--font-mono)'
                }}>
                  <div>
                    <span style={{ color: 'var(--gg-text-3)', fontSize: 10 }}>Target Host</span>
                    <div style={{ fontWeight: 700, color: 'var(--gg-text)' }}>{selectedCluster.src_ip}</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--gg-text-3)', fontSize: 10 }}>Correlated Risk</span>
                    <div style={{ fontWeight: 700, color: '#f87171' }}>{(selectedCluster.correlated_score * 100).toFixed(1)}%</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--gg-text-3)', fontSize: 10 }}>Distinct Vectors</span>
                    <div style={{ fontWeight: 700, color: 'var(--gg-cyan)' }}>{selectedCluster.threat_categories.length} Vectors</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--gg-text-3)', fontSize: 10 }}>Status</span>
                    <div style={{ fontWeight: 700, color: '#34d399' }}>{selectedCluster.status}</div>
                  </div>
                </div>

                {/* 2. Attack Story Narrative */}
                <div style={{
                  padding: 14, borderRadius: 'var(--gg-radius-sm)',
                  background: 'rgba(6, 182, 212, 0.05)', border: '1px solid rgba(6, 182, 212, 0.2)'
                }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: '#22d3ee', textTransform: 'uppercase', marginBottom: 4, letterSpacing: '0.06em' }}>
                    Forensic Correlation Narrative
                  </div>
                  <p style={{ fontSize: 12, color: 'var(--gg-text-2)', lineHeight: 1.5, margin: 0 }}>
                    {selectedCluster.narrative}
                  </p>
                </div>

                {/* 3. Attack Progression Visualizer */}
                <div>
                  <span className="gg-label" style={{ marginBottom: 8 }}>Observed Progression Timeline</span>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {selectedCluster.timeline.map((evt, idx) => {
                      const col = CATEGORY_COLORS[evt.threat_category] ?? 'var(--gg-text)';
                      return (
                        <div
                          key={evt.flow_id || idx}
                          style={{
                            display: 'flex', alignItems: 'flex-start', gap: 12,
                            padding: '10px 12px', borderRadius: 6,
                            background: 'rgba(255,255,255,0.02)', border: '1px solid var(--gg-border)',
                            fontFamily: 'var(--font-mono)'
                          }}
                        >
                          <div style={{ fontSize: 11, color: 'var(--gg-text-3)', width: 64, flexShrink: 0 }}>
                            {fmtTime(evt.timestamp)}
                          </div>
                          <div style={{ flex: 1 }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                              <span style={{ fontSize: 12, fontWeight: 700, color: col }}>
                                {evt.threat_category}
                              </span>
                              <span style={{ fontSize: 10, color: 'var(--gg-text-3)' }}>
                                Risk: {(evt.risk_score * 100).toFixed(0)}% · Conf: {(evt.confidence * 100).toFixed(0)}%
                              </span>
                            </div>
                            <div style={{ fontSize: 11, color: 'var(--gg-text-3)', marginTop: 2 }}>
                              {evt.src_ip} → {evt.dst_ip}:{evt.dst_port}
                            </div>
                            <div style={{ fontSize: 11, color: 'var(--gg-text-2)', marginTop: 4, fontStyle: 'italic' }}>
                              Evidence: {evt.key_evidence}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* 4. Operational Monitoring Status */}
                <div style={{
                  padding: '10px 14px', borderRadius: 6,
                  background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.2)',
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center'
                }}>
                  <span style={{ fontSize: 11, color: 'var(--gg-text-2)' }}>
                    Continuous Operations Guarantee:
                  </span>
                  <div style={{ display: 'flex', gap: 8, fontSize: 10, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                    <span style={{ color: '#34d399' }}>PASSIVE MONITORING: ACTIVE</span>
                    <span style={{ color: 'var(--gg-text-3)' }}>·</span>
                    <span style={{ color: '#38bdf8' }}>ACTIVE RESPONSE: NONE</span>
                  </div>
                </div>

              </div>
            )}

          </div>
        )}

      </div>
      
      {selectedAlert && <AlertDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} />}
    </div>
  );
}
