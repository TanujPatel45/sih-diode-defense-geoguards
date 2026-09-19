'use client';

import { ArrowDown, ShieldCheck } from 'lucide-react';

export function NetworkTopology({ oneWaySafe = true }: { oneWaySafe?: boolean }) {
  const nodes = [
    {
      label: 'PROTECTED NETWORK',
      sub: 'Industrial / Operational Subnet',
      color: '#22d3ee',
      glow: 'rgba(6,182,212,0.2)',
      bg: 'rgba(6,182,212,0.06)',
      border: 'rgba(6,182,212,0.3)',
    },
    {
      label: 'ONE-WAY DATA BOUNDARY',
      sub: 'Hardware-Enforced Diode Boundary',
      color: '#f59e0b',
      glow: 'rgba(245,158,11,0.2)',
      bg: 'rgba(245,158,11,0.06)',
      border: 'rgba(245,158,11,0.3)',
    },
    {
      label: 'GEOGUARDS MONITORING',
      sub: 'Passive Software Monitoring Layer',
      color: '#34d399',
      glow: 'rgba(16,185,129,0.2)',
      bg: 'rgba(16,185,129,0.06)',
      border: 'rgba(16,185,129,0.3)',
    },
    {
      label: 'SOC INVESTIGATION',
      sub: 'Analyst Attack Story & Evidence',
      color: '#a78bfa',
      glow: 'rgba(167,139,250,0.2)',
      bg: 'rgba(167,139,250,0.06)',
      border: 'rgba(167,139,250,0.3)',
    },
  ];

  return (
    <div>
      {/* ── Visual Flow Pipeline ── */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch', gap: 0 }}>
        {nodes.map((node, i) => (
          <div key={node.label}>
            <div style={{
              padding: '11px 14px',
              border: `1px solid ${node.border}`,
              borderRadius: 'var(--gg-radius-sm)',
              background: node.bg,
              backdropFilter: 'blur(12px)',
              WebkitBackdropFilter: 'blur(12px)',
              boxShadow: `0 4px 16px rgba(0,0,0,0.3), 0 0 10px ${node.glow}`,
              transition: 'all 0.2s ease',
            }}>
              <div style={{
                fontSize: 10,
                fontWeight: 800,
                color: node.color,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                textShadow: `0 0 10px ${node.color}66`,
              }}>
                {node.label}
              </div>
              <div style={{ fontSize: 10, color: 'var(--gg-text-3)', marginTop: 2 }}>{node.sub}</div>
            </div>
            {i < nodes.length - 1 && (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '2px 0' }}>
                <div style={{ width: 1, height: 5, background: 'rgba(255,255,255,0.1)' }} />
                <ArrowDown size={12} color="var(--gg-cyan)" className="animate-flow-down" />
                <div style={{ width: 1, height: 5, background: 'rgba(255,255,255,0.1)' }} />
              </div>
            )}
          </div>
        ))}
      </div>

      {/* ── Formal Status Grid ── */}
      <div style={{
        marginTop: 14,
        padding: '12px 14px',
        borderRadius: 'var(--gg-radius-sm)',
        background: 'rgba(0, 0, 0, 0.25)',
        border: '1px solid var(--gg-border)',
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
      }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--gg-text-3)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
          Software representation of a unidirectional architecture
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, fontSize: 10, fontFamily: 'var(--font-mono)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 6px', background: 'rgba(255,255,255,0.02)', borderRadius: 4 }}>
            <span style={{ color: 'var(--gg-text-3)' }}>ONE-WAY MODE:</span>
            <span style={{ color: '#34d399', fontWeight: 700 }}>{oneWaySafe ? 'ACTIVE' : 'INACTIVE'}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 6px', background: 'rgba(255,255,255,0.02)', borderRadius: 4 }}>
            <span style={{ color: 'var(--gg-text-3)' }}>PASSIVE MONITORING:</span>
            <span style={{ color: '#34d399', fontWeight: 700 }}>ACTIVE</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 6px', background: 'rgba(255,255,255,0.02)', borderRadius: 4 }}>
            <span style={{ color: 'var(--gg-text-3)' }}>ACTIVE PROBING:</span>
            <span style={{ color: '#38bdf8', fontWeight: 700 }}>NONE</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 6px', background: 'rgba(255,255,255,0.02)', borderRadius: 4 }}>
            <span style={{ color: 'var(--gg-text-3)' }}>OUTBOUND RESPONSE:</span>
            <span style={{ color: '#38bdf8', fontWeight: 700 }}>NONE</span>
          </div>
        </div>

        <p style={{ fontSize: 10, color: 'var(--gg-muted)', lineHeight: 1.4, margin: '2px 0 0' }}>
          GeoGuards is a passive software monitoring layer designed to operate behind a hardware-enforced unidirectional boundary. GeoGuards does not actively interfere with network traffic.
        </p>
      </div>
    </div>
  );
}
