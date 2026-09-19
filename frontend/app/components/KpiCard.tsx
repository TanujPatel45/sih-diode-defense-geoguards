import type { ReactNode } from 'react';

interface KpiCardProps {
  label:     string;
  value:     string | number | null;
  unit?:     string;
  icon:      ReactNode;
  iconColor: string;
  note?:     string;
  warning?:  boolean;
}

export function KpiCard({ label, value, unit, icon, iconColor, note, warning }: KpiCardProps) {
  return (
    <div
      className="gg-card"
      style={{
        padding: '22px 20px',
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Ambient background glow orb behind the icon */}
      <div
        style={{
          position: 'absolute',
          top: -20,
          right: -20,
          width: 100,
          height: 100,
          borderRadius: '50%',
          background: `radial-gradient(circle, ${iconColor}18 0%, transparent 70%)`,
          pointerEvents: 'none',
        }}
      />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span className="gg-label">{label}</span>
        <div
          style={{
            width: 32,
            height: 32,
            borderRadius: 'var(--gg-radius-sm)',
            background: `${iconColor}12`,
            border: `1px solid ${iconColor}33`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: iconColor,
            boxShadow: `0 0 12px ${iconColor}22, inset 0 1px 0 rgba(255,255,255,0.1)`,
          }}
        >
          {icon}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
        {value !== null && value !== undefined ? (
          <>
            <span
              style={{
                fontSize: 28,
                fontWeight: 800,
                color: warning ? '#f87171' : 'var(--gg-text)',
                letterSpacing: '-0.02em',
                textShadow: warning ? '0 0 16px rgba(239, 68, 68, 0.4)' : 'none',
              }}
            >
              {value}
            </span>
            {unit && (
              <span style={{ fontSize: 11, color: 'var(--gg-text-3)', fontWeight: 500 }}>{unit}</span>
            )}
          </>
        ) : (
          <span style={{ fontSize: 20, color: 'var(--gg-muted)', fontWeight: 400 }}>—</span>
        )}
      </div>

      {note && (
        <p style={{ fontSize: 10, color: 'var(--gg-muted)', marginTop: -4 }}>{note}</p>
      )}
    </div>
  );
}
