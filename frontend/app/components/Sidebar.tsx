'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Shield, Activity, AlertTriangle, Database,
  Cpu, BarChart2, FileCode, Zap, Radio, GitCommit,
} from 'lucide-react';

const NAV = [
  { href: '/',           label: 'Overview',          icon: Shield },
  { href: '/monitor',    label: 'Live Monitor',       icon: Activity },
  { href: '/threats',    label: 'Threats',            icon: AlertTriangle },
  { href: '/stories',    label: 'Attack Stories',     icon: GitCommit },
  { href: '/flows',      label: 'Flow Explorer',      icon: Database },
  { href: '/detection',  label: 'Detection Engine',   icon: Cpu },
  { href: '/analytics',  label: 'Analytics',          icon: BarChart2 },
  { href: '/pcap',       label: 'PCAP Analysis',      icon: FileCode },
  { href: '/demo',       label: 'Demo Lab',           icon: Zap },
];

export function Sidebar() {
  const path = usePathname();

  return (
    <aside
      style={{
        width: 228,
        minWidth: 228,
        background: 'rgba(7, 12, 24, 0.65)',
        backdropFilter: 'var(--glass-blur-heavy)',
        WebkitBackdropFilter: 'var(--glass-blur-heavy)',
        borderRight: '1px solid var(--gg-border)',
        boxShadow: '4px 0 24px rgba(0, 0, 0, 0.4)',
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        position: 'sticky',
        top: 0,
        zIndex: 20,
      }}
    >
      {/* Brand Header */}
      <div style={{
        padding: '22px 20px 18px',
        borderBottom: '1px solid var(--gg-border)',
        position: 'relative',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 11, marginBottom: 4 }}>
          <div style={{
            width: 32, height: 32,
            background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.2), rgba(6, 182, 212, 0.2))',
            border: '1px solid rgba(16, 185, 129, 0.4)',
            borderRadius: 9,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 16px rgba(16, 185, 129, 0.25), inset 0 1px 0 rgba(255,255,255,0.2)',
          }}>
            <Radio size={15} color="var(--gg-green)" />
          </div>
          <div>
            <div style={{
              fontWeight: 800,
              fontSize: 14,
              letterSpacing: '0.12em',
              background: 'linear-gradient(90deg, #34d399, #22d3ee)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              textTransform: 'uppercase',
            }}>GeoGuards</div>
          </div>
        </div>
        <div style={{
          fontSize: 9,
          color: 'var(--gg-muted)',
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
          fontWeight: 600,
          paddingLeft: 2,
        }}>
          Passive Cyber Intelligence
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: '14px 10px', overflowY: 'auto' }}>
        {NAV.map(({ href, label, icon: Icon }) => {
          const active = href === '/' ? path === '/' : path.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 11,
                padding: '9px 13px',
                borderRadius: 'var(--gg-radius-sm)',
                marginBottom: 3,
                fontSize: 13,
                fontWeight: active ? 600 : 400,
                color: active ? '#ffffff' : 'var(--gg-text-2)',
                background: active
                  ? 'linear-gradient(90deg, rgba(16, 185, 129, 0.15) 0%, rgba(6, 182, 212, 0.08) 100%)'
                  : 'transparent',
                border: active
                  ? '1px solid rgba(16, 185, 129, 0.3)'
                  : '1px solid transparent',
                boxShadow: active
                  ? '0 2px 12px rgba(0, 0, 0, 0.2), inset 0 1px 0 rgba(255,255,255,0.1), 0 0 12px rgba(16, 185, 129, 0.1)'
                  : 'none',
                textDecoration: 'none',
                transition: 'all 0.18s cubic-bezier(0.16, 1, 0.3, 1)',
                cursor: 'pointer',
                position: 'relative',
              }}
            >
              <Icon
                size={15}
                color={active ? '#34d399' : 'var(--gg-muted)'}
                style={{
                  flexShrink: 0,
                  filter: active ? 'drop-shadow(0 0 6px rgba(16, 185, 129, 0.5))' : 'none',
                }}
              />
              <span style={{ flex: 1 }}>{label}</span>
              {active && (
                <div style={{
                  width: 4, height: 14, borderRadius: 2,
                  background: 'var(--gg-green)',
                  boxShadow: '0 0 8px rgba(16, 185, 129, 0.8)',
                }} />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div style={{
        padding: '14px 20px',
        borderTop: '1px solid var(--gg-border)',
        fontSize: 10,
        color: 'var(--gg-muted)',
        letterSpacing: '0.08em',
        background: 'rgba(4, 8, 16, 0.3)',
      }}>
        <div style={{ fontWeight: 600, color: 'var(--gg-text-3)' }}>SIH 2026 · PS 26145</div>
        <div style={{ marginTop: 2, color: 'var(--gg-muted)' }}>Team Innov8</div>
      </div>
    </aside>
  );
}
