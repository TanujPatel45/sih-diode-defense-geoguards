'use client';

import { useEffect, useState } from 'react';
import { API } from '../lib/api';

interface TopBarProps {
  title: string;
  subtitle?: string;
}

export function TopBar({ title, subtitle }: TopBarProps) {
  const [apiOk, setApiOk]   = useState<boolean | null>(null);
  const [model, setModel]   = useState<string>('');

  useEffect(() => {
    let mounted = true;
    const check = async () => {
      try {
        const h = await API.health();
        if (mounted) {
          setApiOk(h.status === 'ok');
          setModel(h.model_version ?? '');
        }
      } catch {
        if (mounted) {
          setApiOk(false);
        }
      }
    };
    check();
    const id = setInterval(check, 5000);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '16px 28px',
      borderBottom: '1px solid var(--gg-border)',
      background: 'rgba(7, 12, 24, 0.6)',
      backdropFilter: 'var(--glass-blur)',
      WebkitBackdropFilter: 'var(--glass-blur)',
      boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
      position: 'sticky',
      top: 0,
      zIndex: 15,
    }}>
      <div>
        <h1 style={{
          fontSize: 16,
          fontWeight: 700,
          color: 'var(--gg-text)',
          letterSpacing: '-0.02em',
        }}>
          {title}
        </h1>
        {subtitle && (
          <p style={{ fontSize: 11, color: 'var(--gg-text-3)', marginTop: 2 }}>{subtitle}</p>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        {/* API status glass pill */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 7,
          padding: '6px 14px',
          borderRadius: 24,
          border: `1px solid ${
            apiOk === true ? 'rgba(16,185,129,0.35)' :
            apiOk === false ? 'rgba(239,68,68,0.35)' :
            'var(--gg-border)'
          }`,
          background: apiOk === true
            ? 'rgba(16,185,129,0.08)'
            : apiOk === false
            ? 'rgba(239,68,68,0.08)'
            : 'rgba(255,255,255,0.03)',
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
          boxShadow: apiOk === true
            ? '0 0 16px rgba(16,185,129,0.12), inset 0 1px 0 rgba(255,255,255,0.1)'
            : 'none',
          fontSize: 11,
          fontWeight: 600,
          letterSpacing: '0.06em',
          textTransform: 'uppercase' as const,
          color: apiOk === true ? '#34d399' : apiOk === false ? '#f87171' : 'var(--gg-muted)',
        }}>
          <span style={{
            width: 7, height: 7, borderRadius: '50%',
            background: apiOk === true ? 'var(--gg-green)' : apiOk === false ? 'var(--gg-red)' : 'var(--gg-muted)',
            boxShadow: apiOk === true ? '0 0 8px rgba(16,185,129,0.8)' : 'none',
            ...(apiOk === true ? { animation: 'pulse-dot 1.6s ease-in-out infinite' } : {}),
          }} />
          {apiOk === true ? 'System Operational' : apiOk === false ? 'API Offline' : 'Connecting…'}
        </div>

        {/* One-way indicator glass capsule */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '6px 14px',
          borderRadius: 24,
          border: '1px solid rgba(6,182,212,0.35)',
          background: 'rgba(6,182,212,0.08)',
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
          boxShadow: '0 0 16px rgba(6,182,212,0.12), inset 0 1px 0 rgba(255,255,255,0.1)',
          fontSize: 11, fontWeight: 600,
          letterSpacing: '0.06em',
          textTransform: 'uppercase' as const,
          color: '#22d3ee',
        }}>
          ↓ One-Way Ingestion
        </div>

        {/* Model version */}
        {model && (
          <div style={{
            padding: '5px 10px',
            borderRadius: 6,
            background: 'rgba(255,255,255,0.03)',
            border: '1px solid var(--gg-border)',
            fontSize: 10,
            color: 'var(--gg-muted)',
            fontFamily: 'var(--font-mono)',
          }}>
            {model}
          </div>
        )}
      </div>
    </div>
  );
}
