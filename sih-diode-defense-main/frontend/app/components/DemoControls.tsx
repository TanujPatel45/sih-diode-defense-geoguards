'use client';

import { useState, useCallback } from 'react';
import { API } from '../lib/api';
import { Zap, ShieldAlert, Radio, Activity, RefreshCw } from 'lucide-react';

const PROFILES: Record<string, object> = {
  normal: {
    source_ip: '10.0.1.10', destination_ip: '10.0.0.1',
    source_port: 54321, destination_port: 80, protocol: 6,
    iat_mean: 0.99, iat_std: 1.42, pkt_len_mean: 100.0, pkt_len_std: 132.0,
    payload_entropy: 4.97, syn_ratio: 0.02, tcp_rst_ratio: 0.01, tcp_fin_ratio: 0.05,
    duration: 10.0, packet_count: 50, byte_count: 5000,
    forward_pkts: 25, backward_pkts: 25, forward_bytes: 2500, backward_bytes: 2500,
    analysis_mode: 'demo_simulation',
  },
  syn_flood: {
    source_ip: '10.0.4.182', destination_ip: '10.0.0.1',
    source_port: 12345, destination_port: 80, protocol: 6,
    iat_mean: 0.0003, iat_std: 0.00005, pkt_len_mean: 64, pkt_len_std: 2,
    payload_entropy: 0.15, syn_ratio: 0.99, tcp_rst_ratio: 0.0, tcp_fin_ratio: 0.0,
    duration: 0.5, packet_count: 800, byte_count: 51200,
    forward_pkts: 800, backward_pkts: 0, forward_bytes: 51200, backward_bytes: 0,
    analysis_mode: 'demo_simulation',
  },
  dns_tunnel: {
    source_ip: '192.168.10.45', destination_ip: '8.8.8.8',
    source_port: 45678, destination_port: 53, protocol: 17,
    iat_mean: 0.08, iat_std: 0.02, pkt_len_mean: 190, pkt_len_std: 35,
    payload_entropy: 7.9, syn_ratio: 0.0, tcp_rst_ratio: 0.0, tcp_fin_ratio: 0.0,
    duration: 5.0, packet_count: 60, byte_count: 11400,
    forward_pkts: 30, backward_pkts: 30, forward_bytes: 5700, backward_bytes: 5700,
    dns_query: 'exfiltratedchunk38472918.tunnel.victim.com',
    analysis_mode: 'demo_simulation',
  },
  c2_beacon: {
    source_ip: '172.16.0.88', destination_ip: '91.195.240.117',
    source_port: 55123, destination_port: 443, protocol: 6,
    iat_mean: 2.001, iat_std: 0.0001, pkt_len_mean: 125, pkt_len_std: 5,
    payload_entropy: 4.1, syn_ratio: 0.0, tcp_rst_ratio: 0.01, tcp_fin_ratio: 0.02,
    duration: 120.0, packet_count: 60, byte_count: 7500,
    forward_pkts: 30, backward_pkts: 30, forward_bytes: 3750, backward_bytes: 3750,
    analysis_mode: 'demo_simulation',
  },
};

const ATTACK_PRESETS = [
  { id: 'mixed',      label: '⚡ Mixed Threat Burst', desc: 'Cycles all attack signatures in rapid sequence', color: '#22d3ee', border: 'rgba(6,182,212,0.4)', bg: 'rgba(6,182,212,0.12)' },
  { id: 'syn_flood',  label: '🔴 SYN / UDP Flood',    desc: 'Volumetric low-IAT SYN storm on port 80',         color: '#f87171', border: 'rgba(239,68,68,0.4)',  bg: 'rgba(239,68,68,0.12)' },
  { id: 'dns_tunnel', label: '🔵 DNS Tunneling',      desc: 'High-entropy payload exfiltration on UDP 53',     color: '#38bdf8', border: 'rgba(56,189,248,0.4)', bg: 'rgba(56,189,248,0.12)' },
  { id: 'c2_beacon',  label: '🟠 C2 Beaconing',       desc: 'Periodic zero-jitter heartbeat to external IP',   color: '#fb923c', border: 'rgba(249,115,22,0.4)', bg: 'rgba(249,115,22,0.12)' },
  { id: 'normal',     label: '🟢 Benign Baseline',    desc: 'Legitimate regular traffic (expected Benign)',    color: '#34d399', border: 'rgba(16,185,129,0.4)', bg: 'rgba(16,185,129,0.12)' },
];

export function DemoControls({ onRefresh }: { onRefresh?: () => void }) {
  const [selectedId, setSelectedId] = useState('mixed');
  const [count, setCount]           = useState(10);
  const [running, setRunning]       = useState(false);
  const [status, setStatus]         = useState('');
  const [progress, setProgress]     = useState(0);

  const inject = useCallback(async (presetId = selectedId, flowCount = count) => {
    if (running) return;
    setRunning(true);
    setProgress(0);
    setStatus(`Initializing synthetic simulation injection (${flowCount} flows)…`);

    const cycle =
      presetId === 'mixed'
        ? ['syn_flood', 'dns_tunnel', 'c2_beacon', 'normal']
        : [presetId];

    let ok = 0;

    for (let i = 0; i < flowCount; i++) {
      const profileKey = cycle[i % cycle.length];
      const payload    = { ...PROFILES[profileKey] };

      try {
        await API.analyzeFlow(payload as Record<string, unknown>);
        ok++;
        setProgress(Math.round(((i + 1) / flowCount) * 100));
        setStatus(`Injecting stream: ${i + 1}/${flowCount} flows evaluated by real backend…`);
      } catch {
        setStatus('Connection error — check backend API status.');
        break;
      }
      await new Promise((r) => setTimeout(r, 150));
    }

    setStatus(`✓ Complete: ${ok}/${flowCount} synthetic demo flows evaluated & stored.`);
    setRunning(false);
    onRefresh?.();
  }, [running, selectedId, count, onRefresh]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Simulation Banner */}
      <div style={{
        padding: '10px 14px',
        borderRadius: 'var(--gg-radius-sm)',
        background: 'rgba(251, 191, 36, 0.08)',
        border: '1px solid rgba(251, 191, 36, 0.25)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        fontSize: 11,
        color: '#fbbf24'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Activity size={14} />
          <span><strong>DEMO / SIMULATION MODE:</strong> Injects deterministic synthetic flow vectors into the live backend detection pipeline for testing.</span>
        </div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10 }}>Analysis Mode: synthetic_demo</span>
      </div>

      {/* Attack Presets Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10 }}>
        {ATTACK_PRESETS.map((preset) => {
          const active = selectedId === preset.id;
          return (
            <div
              key={preset.id}
              onClick={() => setSelectedId(preset.id)}
              style={{
                padding: '14px 16px',
                borderRadius: 'var(--gg-radius-sm)',
                border: `1px solid ${active ? preset.border : 'var(--gg-border)'}`,
                background: active ? preset.bg : 'rgba(255, 255, 255, 0.025)',
                backdropFilter: 'blur(12px)',
                WebkitBackdropFilter: 'blur(12px)',
                boxShadow: active ? `0 0 20px ${preset.color}22, inset 0 1px 0 rgba(255,255,255,0.1)` : 'none',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: active ? preset.color : 'var(--gg-text)' }}>
                  {preset.label}
                </span>
                {active && <span className="status-dot status-dot-cyan animate-pulse-dot" />}
              </div>
              <p style={{ fontSize: 11, color: 'var(--gg-text-3)', lineHeight: 1.4 }}>
                {preset.desc}
              </p>
            </div>
          );
        })}
      </div>

      {/* Control Bar with Flow Counter & Trigger */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 14,
        padding: '16px 20px',
        borderRadius: 'var(--gg-radius-sm)',
        background: 'rgba(255, 255, 255, 0.025)',
        border: '1px solid var(--gg-border)',
      }}>
        {/* Count Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="gg-label">Burst Volume:</span>
          <div style={{ display: 'flex', gap: 6 }}>
            {[5, 10, 25, 50].map((n) => (
              <button
                key={n}
                onClick={() => setCount(n)}
                style={{
                  padding: '5px 12px',
                  borderRadius: 6,
                  border: `1px solid ${count === n ? 'rgba(6,182,212,0.45)' : 'var(--gg-border)'}`,
                  background: count === n ? 'rgba(6,182,212,0.15)' : 'rgba(255,255,255,0.03)',
                  color: count === n ? '#22d3ee' : 'var(--gg-text-2)',
                  fontSize: 11,
                  fontWeight: 700,
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                {n}
              </button>
            ))}
          </div>
        </div>

        {/* Action Button */}
        <button
          id="demo-inject-button"
          onClick={() => inject(selectedId, count)}
          disabled={running}
          className="gg-glass-btn gg-glass-btn-primary"
          style={{
            padding: '10px 24px',
            fontSize: 13,
            fontWeight: 700,
            opacity: running ? 0.7 : 1,
          }}
        >
          {running ? (
            <>
              <RefreshCw size={15} className="animate-spin" />
              <span>Evaluating Stream ({progress}%)…</span>
            </>
          ) : (
            <>
              <Zap size={15} />
              <span>Launch Live Attack Injection</span>
            </>
          )}
        </button>
      </div>

      {/* Progress Bar & Status Ticker */}
      {(running || status) && (
        <div style={{
          padding: '12px 16px',
          borderRadius: 'var(--gg-radius-sm)',
          background: 'rgba(6, 182, 212, 0.05)',
          border: '1px solid rgba(6, 182, 212, 0.2)',
          display: 'flex',
          flexDirection: 'column',
          gap: 8,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: '#22d3ee', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
              {status}
            </span>
            <span style={{ fontSize: 11, color: 'var(--gg-text-3)', fontFamily: 'var(--font-mono)' }}>
              {progress}%
            </span>
          </div>
          <div style={{
            height: 4,
            background: 'rgba(255, 255, 255, 0.08)',
            borderRadius: 2,
            overflow: 'hidden',
          }}>
            <div style={{
              height: '100%',
              width: `${progress}%`,
              background: 'linear-gradient(90deg, #10b981, #06b6d4)',
              boxShadow: '0 0 10px rgba(6,182,212,0.8)',
              borderRadius: 2,
              transition: 'width 0.2s ease',
            }} />
          </div>
        </div>
      )}
    </div>
  );
}
