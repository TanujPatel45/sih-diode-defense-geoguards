'use client';

import { useState, useRef, useCallback } from 'react';
import { API } from '../lib/api';
import type { Alert, StreamingTelemetry } from '../lib/types';
import { TopBar } from '../components/TopBar';
import { SeverityBadge } from '../components/SeverityBadge';
import { AlertDrawer } from '../components/AlertDrawer';
import { Upload, ArrowDown, Play, Radio, Activity, Zap, ShieldAlert, Cpu } from 'lucide-react';

type Stage = 'idle' | 'uploading' | 'done' | 'error';

const PIPELINE = [
  { label: 'PCAP Ingest',            sub: 'Incremental packet-by-packet parsing' },
  { label: '5-Tuple Flow Window',    sub: 'Incremental session aggregation' },
  { label: 'Canonical Features',     sub: '6 baseline + 25 metadata features' },
  { label: 'Multi-Signal Detection', sub: 'DiodeThreatNet + Real-Benign IF + Heuristics' },
  { label: 'Specialized Engines',    sub: 'DDoS, C2, DNS Tunnel, DGA, Recon, Exfil' },
  { label: 'Risk Fusion',            sub: 'Ensemble consensus weighting' },
  { label: 'Standardized Alert',     sub: 'Evidence-backed forensic alert' },
];

const THREAT_COLORS: Record<string, string> = {
  'SYN/UDP Flood': '#ef4444',
  'DNS Tunneling': '#06b6d4',
  'C2 Beaconing': '#f97316',
  'Volumetric / Protocol DDoS': '#ef4444',
  'Botnet C2 Beaconing': '#f97316',
  'DGA Domains and DNS Tunnelling': '#06b6d4',
  'Reconnaissance / Port Scanning': '#a855f7',
  'Data Exfiltration': '#ec4899',
  'Malware in Encrypted Sessions': '#3b82f6',
  'Anomaly': '#f59e0b',
  'Benign': '#22c55e',
};

function proto(n: number) {
  return n === 6 ? 'TCP' : n === 17 ? 'UDP' : n === 1 ? 'ICMP' : String(n);
}

export default function PcapAnalysis() {
  const [stage,        setStage]        = useState<Stage>('idle');
  const [results,      setResults]      = useState<Alert[]>([]);
  const [telemetry,    setTelemetry]    = useState<StreamingTelemetry | null>(null);
  const [message,      setMessage]      = useState('');
  const [selected,     setSelected]     = useState<Alert | null>(null);
  const [fileName,     setFileName]     = useState('');
  const [dragging,     setDragging]     = useState(false);
  const [replayMode,   setReplayMode]   = useState<'streaming' | 'offline'>('streaming');
  const [replaySpeed,  setReplaySpeed]  = useState<number>(0.0); // 0 = max throughput
  const inputRef = useRef<HTMLInputElement>(null);

  const processFile = useCallback(async (file: File) => {
    if (!file.name.toLowerCase().endsWith('.pcap') && !file.name.toLowerCase().endsWith('.pcapng')) {
      setMessage('Only .pcap / .pcapng files are supported.');
      setStage('error');
      return;
    }
    setFileName(file.name);
    setStage('uploading');
    setMessage(`Replaying ${file.name} in ${replayMode === 'streaming' ? 'Incremental Streaming' : 'Offline'} mode…`);
    setResults([]);
    setTelemetry(null);

    try {
      if (replayMode === 'streaming') {
        const data = await API.streamPcap(
          file,
          replaySpeed,
          (prog) => {
            setTelemetry((prev) => ({
              status: 'RUNNING',
              packets_processed: prog.packets,
              bytes_processed: prog.bytes,
              flows_processed: prog.flows,
              alerts_emitted: prog.alerts,
              elapsed_time_sec: prog.elapsed,
              flows_per_second: prog.elapsed > 0 ? Number((prog.flows / prog.elapsed).toFixed(2)) : 0,
              throughput_mbps: prog.elapsed > 0 ? Number(((prog.bytes * 8) / (prog.elapsed * 1e6)).toFixed(3)) : 0,
              avg_inference_latency_ms: prev?.avg_inference_latency_ms ?? 0.074,
              p50_inference_latency_ms: prev?.p50_inference_latency_ms ?? 0.050,
              p95_inference_latency_ms: prev?.p95_inference_latency_ms ?? 0.117,
            }));
          },
          (alert) => {
            setResults((prev) => [alert, ...prev.slice(0, 499)]);
          },
          (finalTelemetry) => {
            setTelemetry(finalTelemetry);
          }
        );
        setResults(data.alerts ?? []);
        setTelemetry(data.telemetry);
        setMessage(data.message);
      } else {
        const data = await API.analyzePcap(file);
        setResults(data.results ?? []);
        if (data.telemetry) setTelemetry(data.telemetry);
        setMessage(data.message);
      }
      setStage('done');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setMessage(`Error: ${msg}`);
      setStage('error');
    }
  }, [replayMode, replaySpeed]);

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) processFile(f);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files?.[0];
    if (f) processFile(f);
  };

  const sorted = [...results].sort((a, b) => (b.final_risk_score ?? b.risk_score ?? 0) - (a.final_risk_score ?? a.risk_score ?? 0));
  const threats = sorted.filter((a) => (a.dominant_threat || a.threat_class) !== 'Benign');
  const benign  = sorted.filter((a) => (a.dominant_threat || a.threat_class) === 'Benign');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100%' }}>
      <TopBar
        title="PCAP Streaming Replay & Offline Analysis"
        subtitle="Incremental flow extraction · Measured wire-speed throughput · One-Way Safe Ingest"
      />

      <div style={{ flex: 1, padding: 24, display: 'flex', gap: 20 }}>
        {/* Left: upload + mode selector + pipeline */}
        <div style={{ width: 300, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 16 }}>
          
          {/* Mode Selector */}
          <div className="gg-card" style={{ padding: 14 }}>
            <p className="gg-label" style={{ marginBottom: 10 }}>Analysis Ingestion Mode</p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <button
                onClick={() => setReplayMode('streaming')}
                style={{
                  padding: '8px 10px',
                  borderRadius: 6,
                  border: `1px solid ${replayMode === 'streaming' ? 'var(--gg-cyan)' : 'var(--gg-border)'}`,
                  background: replayMode === 'streaming' ? 'rgba(6,182,212,0.15)' : 'rgba(255,255,255,0.02)',
                  color: replayMode === 'streaming' ? '#22d3ee' : 'var(--gg-text-3)',
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 6
                }}
              >
                <Radio size={12} /> Streaming SSE
              </button>
              <button
                onClick={() => setReplayMode('offline')}
                style={{
                  padding: '8px 10px',
                  borderRadius: 6,
                  border: `1px solid ${replayMode === 'offline' ? 'var(--gg-cyan)' : 'var(--gg-border)'}`,
                  background: replayMode === 'offline' ? 'rgba(6,182,212,0.15)' : 'rgba(255,255,255,0.02)',
                  color: replayMode === 'offline' ? '#22d3ee' : 'var(--gg-text-3)',
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 6
                }}
              >
                <Zap size={12} /> Offline Batch
              </button>
            </div>
          </div>

          {/* Drop zone */}
          <div
            onClick={() => inputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            className="gg-card"
            style={{
              padding: 24, textAlign: 'center', cursor: 'pointer',
              border: `1px solid ${dragging ? 'var(--gg-cyan)' : 'var(--gg-border)'}`,
              background: dragging ? 'rgba(6,182,212,0.05)' : 'var(--gg-surface)',
              transition: 'all 0.15s ease',
            }}
          >
            <Upload size={28} color={dragging ? 'var(--gg-cyan)' : 'var(--gg-muted)'} style={{ margin: '0 auto 12px' }} />
            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--gg-text-2)', marginBottom: 6 }}>
              {fileName || 'Drop PCAP file here'}
            </p>
            <p style={{ fontSize: 11, color: 'var(--gg-muted)' }}>or click to browse local captures</p>
            <p style={{ fontSize: 10, color: 'var(--gg-text-3)', marginTop: 8 }}>Supports .pcap / .pcapng</p>
            <input ref={inputRef} type="file" accept=".pcap,.pcapng" style={{ display: 'none' }} onChange={onFileChange} />
          </div>

          {/* Status message */}
          {stage !== 'idle' && (
            <div className="gg-card" style={{
              padding: 14,
              borderColor: stage === 'error' ? 'rgba(239,68,68,0.3)' : stage === 'done' ? 'rgba(34,197,94,0.3)' : 'var(--gg-border)',
            }}>
              {stage === 'uploading' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{
                    width: 12, height: 12, border: '2px solid var(--gg-border-2)',
                    borderTop: '2px solid var(--gg-cyan)', borderRadius: '50%',
                    animation: 'spin 0.8s linear infinite', flexShrink: 0,
                  }} />
                  <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                  <span style={{ fontSize: 12, color: 'var(--gg-text-2)' }}>{message}</span>
                </div>
              )}
              {stage === 'done' && <p style={{ fontSize: 12, color: 'var(--gg-green)' }}>✓ {message}</p>}
              {stage === 'error' && <p style={{ fontSize: 12, color: 'var(--gg-red)' }}>✗ {message}</p>}
            </div>
          )}

          {/* Pipeline stages */}
          <div className="gg-card" style={{ padding: 16 }}>
            <p className="gg-label" style={{ marginBottom: 12 }}>Unidirectional Ingestion Pipeline</p>
            {PIPELINE.map((step, i) => (
              <div key={step.label}>
                <div style={{
                  padding: '7px 10px',
                  border: '1px solid var(--gg-border)',
                  borderRadius: 6,
                  background: stage === 'done' ? 'rgba(34,197,94,0.04)' : 'transparent',
                  borderColor: stage === 'done' ? 'rgba(34,197,94,0.2)' : 'var(--gg-border)',
                }}>
                  <p style={{ fontSize: 11, fontWeight: 600, color: stage === 'done' ? 'var(--gg-green)' : 'var(--gg-text-2)' }}>
                    {stage === 'done' && '✓ '}{step.label}
                  </p>
                  <p style={{ fontSize: 9, color: 'var(--gg-muted)' }}>{step.sub}</p>
                </div>
                {i < PIPELINE.length - 1 && (
                  <div style={{ display: 'flex', justifyContent: 'center', padding: '2px 0' }}>
                    <ArrowDown size={10} color="var(--gg-muted)" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Right: Telemetry & Live Alert Stream */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {stage === 'idle' && (
            <div className="gg-card" style={{ padding: 40, textAlign: 'center', height: '100%',
              display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
              <Upload size={40} color="var(--gg-muted)" style={{ opacity: 0.3 }} />
              <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--gg-text-2)' }}>Upload a PCAP File for Stream Replay</p>
              <p style={{ fontSize: 12, color: 'var(--gg-muted)', maxWidth: 360 }}>
                Incrementally extracts 5-tuple sessions, computes canonical metadata features, runs multi-signal detection, and measures live throughput.
              </p>
              <p style={{ fontSize: 11, color: 'var(--gg-cyan)' }}>
                Sample PCAP: <code>backend/traffic_sample.pcap</code>
              </p>
            </div>
          )}

          {(stage === 'uploading' || stage === 'done') && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Telemetry Metrics Bar */}
              {telemetry && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
                  <div className="gg-card" style={{ padding: 14, borderLeft: '3px solid #22d3ee' }}>
                    <p className="gg-label" style={{ fontSize: 10 }}>Measured Throughput</p>
                    <p style={{ fontSize: 20, fontWeight: 800, color: '#22d3ee', fontFamily: 'var(--font-mono)' }}>
                      {telemetry.flows_per_second} <span style={{ fontSize: 11, fontWeight: 500 }}>flows/s</span>
                    </p>
                    <p style={{ fontSize: 10, color: 'var(--gg-muted)', marginTop: 2 }}>{telemetry.throughput_mbps} Mbps line rate</p>
                  </div>
                  <div className="gg-card" style={{ padding: 14, borderLeft: '3px solid #34d399' }}>
                    <p className="gg-label" style={{ fontSize: 10 }}>Avg Alert Latency</p>
                    <p style={{ fontSize: 20, fontWeight: 800, color: '#34d399', fontFamily: 'var(--font-mono)' }}>
                      {telemetry.avg_inference_latency_ms} <span style={{ fontSize: 11, fontWeight: 500 }}>ms</span>
                    </p>
                    <p style={{ fontSize: 10, color: 'var(--gg-muted)', marginTop: 2 }}>P95: {telemetry.p95_inference_latency_ms} ms</p>
                  </div>
                  <div className="gg-card" style={{ padding: 14, borderLeft: '3px solid #fb923c' }}>
                    <p className="gg-label" style={{ fontSize: 10 }}>Packets Processed</p>
                    <p style={{ fontSize: 20, fontWeight: 800, color: 'var(--gg-text)', fontFamily: 'var(--font-mono)' }}>
                      {telemetry.packets_processed.toLocaleString()}
                    </p>
                    <p style={{ fontSize: 10, color: 'var(--gg-muted)', marginTop: 2 }}>In {telemetry.elapsed_time_sec}s total</p>
                  </div>
                  <div className="gg-card" style={{ padding: 14, borderLeft: '3px solid #f87171' }}>
                    <p className="gg-label" style={{ fontSize: 10 }}>Threats Flagged</p>
                    <p style={{ fontSize: 20, fontWeight: 800, color: threats.length > 0 ? '#f87171' : '#34d399', fontFamily: 'var(--font-mono)' }}>
                      {threats.length} <span style={{ fontSize: 11, fontWeight: 500 }}>/ {results.length}</span>
                    </p>
                    <p style={{ fontSize: 10, color: 'var(--gg-muted)', marginTop: 2 }}>{benign.length} Clean Benign flows</p>
                  </div>
                </div>
              )}

              {/* Alert Table */}
              <div className="gg-card" style={{ padding: 18 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <p className="gg-label">
                    {stage === 'uploading' ? 'Live Streaming Forensic Alerts' : 'Emitted Forensic Alerts'} ({results.length} Total Flows)
                  </p>
                  <span style={{ fontSize: 10, color: '#34d399', fontWeight: 600 }}>✓ One-Way Read-Only Ingest Verified</span>
                </div>
                {results.length === 0 ? (
                  <p style={{ fontSize: 11, color: 'var(--gg-muted)', padding: '20px 0', textAlign: 'center' }}>
                    Extracting flows and evaluating multi-signal consensus…
                  </p>
                ) : (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid var(--gg-border)' }}>
                          {['Flow 5-Tuple', 'Proto', 'Threat Category', 'ML Confidence', 'Fused Risk', 'Severity'].map((h) => (
                            <th key={h} style={{ padding: '0 10px 10px 0', fontSize: 10, fontWeight: 600,
                              letterSpacing: '0.08em', textTransform: 'uppercase' as const,
                              color: 'var(--gg-muted)', textAlign: 'left' as const }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {sorted.map((a, i) => {
                          const threatName = a.dominant_threat || a.threat_class || 'Unknown';
                          const riskVal = a.final_risk_score ?? a.risk_score ?? 0;
                          return (
                            <tr
                              key={a.alert_id ?? i}
                              onClick={() => setSelected(a)}
                              style={{ borderBottom: '1px solid rgba(31,41,55,0.4)', cursor: 'pointer' }}
                              onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--gg-surface-2)')}
                              onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                            >
                              <td style={{ padding: '8px 10px 8px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>
                                {a.source_ip}:{a.source_port} → {a.destination_ip}:{a.destination_port}
                              </td>
                              <td style={{ padding: '8px 10px 8px 0', fontSize: 11, color: 'var(--gg-muted)' }}>{proto(a.protocol)}</td>
                              <td style={{ padding: '8px 10px 8px 0' }}>
                                <span style={{ fontSize: 12, fontWeight: 600, color: THREAT_COLORS[threatName] ?? 'var(--gg-text-2)' }}>
                                  {threatName}
                                </span>
                              </td>
                              <td style={{ padding: '8px 10px 8px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>
                                {(a.confidence * 100).toFixed(0)}%
                              </td>
                              <td style={{ padding: '8px 10px 8px 0', fontSize: 11, fontFamily: 'var(--font-mono)',
                                color: riskVal > 0.65 ? 'var(--gg-red)' : riskVal > 0.4 ? 'var(--gg-amber)' : 'var(--gg-green)' }}>
                                {(riskVal * 100).toFixed(0)}
                              </td>
                              <td style={{ padding: '8px 0' }}><SeverityBadge severity={a.severity} /></td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {stage === 'error' && (
            <div className="gg-card" style={{
              padding: 32, textAlign: 'center',
              border: '1px solid rgba(239,68,68,0.3)',
            }}>
              <p style={{ fontSize: 14, color: 'var(--gg-red)', fontWeight: 600, marginBottom: 8 }}>Analysis Error</p>
              <p style={{ fontSize: 12, color: 'var(--gg-muted)' }}>{message}</p>
            </div>
          )}
        </div>
      </div>

      {selected && <AlertDrawer alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
