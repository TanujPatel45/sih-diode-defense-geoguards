export function SeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === 'CRITICAL' ? 'sev-critical' :
    severity === 'HIGH'     ? 'sev-high'     :
    severity === 'MEDIUM'   ? 'sev-medium'   : 'sev-low';

  return (
    <span
      className={cls}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '3px 9px',
        borderRadius: 6,
        fontSize: 10,
        fontWeight: 700,
        letterSpacing: '0.08em',
        textTransform: 'uppercase',
        fontFamily: 'var(--font-ui)',
      }}
    >
      {severity}
    </span>
  );
}

export function RiskBar({ score, severity }: { score: number; severity: string }) {
  const pct   = Math.round(score * 100);
  const color =
    severity === 'CRITICAL' ? '#ef4444' :
    severity === 'HIGH'     ? '#f97316' :
    severity === 'MEDIUM'   ? '#f59e0b' : '#10b981';

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <div style={{
        flex: 1,
        height: 5,
        background: 'rgba(255, 255, 255, 0.05)',
        border: '1px solid rgba(255, 255, 255, 0.05)',
        borderRadius: 3,
        overflow: 'hidden',
        boxShadow: 'inset 0 1px 2px rgba(0,0,0,0.5)',
      }}>
        <div style={{
          height: '100%',
          width: `${pct}%`,
          background: `linear-gradient(90deg, ${color}88, ${color})`,
          boxShadow: `0 0 8px ${color}88`,
          borderRadius: 3,
          transition: 'width 0.3s ease',
        }} />
      </div>
      <span style={{
        fontSize: 11,
        color: color,
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        minWidth: 28,
        textAlign: 'right',
        textShadow: `0 0 8px ${color}66`,
      }}>
        {pct}
      </span>
    </div>
  );
}
