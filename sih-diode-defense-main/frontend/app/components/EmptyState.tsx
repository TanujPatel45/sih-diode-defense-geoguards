import type { ReactNode } from 'react';
import { ShieldCheck, Radar } from 'lucide-react';

interface EmptyStateProps {
  icon?:    ReactNode;
  title:    string;
  message?: string;
  actionLabel?: string;
  onAction?: () => void;
}

export function EmptyState({ icon, title, message, actionLabel, onAction }: EmptyStateProps) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center',
      padding: '40px 24px', gap: 14, textAlign: 'center',
      position: 'relative',
    }}>
      {/* Radar Scanner Visual */}
      <div style={{
        position: 'relative',
        width: 64,
        height: 64,
        borderRadius: '50%',
        border: '1px solid rgba(6, 182, 212, 0.25)',
        background: 'radial-gradient(circle, rgba(6, 182, 212, 0.08) 0%, transparent 70%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        boxShadow: '0 0 24px rgba(6, 182, 212, 0.1)',
        marginBottom: 4,
      }}>
        {/* Animated Sweep Line */}
        <div style={{
          position: 'absolute',
          inset: 0,
          borderRadius: '50%',
          background: 'conic-gradient(from 0deg, rgba(6, 182, 212, 0.4) 0deg, transparent 60deg, transparent 360deg)',
          animation: 'radar-sweep 3s linear infinite',
          pointerEvents: 'none',
        }} />

        {icon ? (
          <div style={{ color: 'var(--gg-cyan)', zIndex: 2 }}>{icon}</div>
        ) : (
          <Radar size={22} color="var(--gg-cyan)" style={{ zIndex: 2 }} />
        )}
      </div>

      <div>
        <p style={{
          fontSize: 13,
          fontWeight: 700,
          color: 'var(--gg-text)',
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
        }}>
          {title}
        </p>
        {message && (
          <p style={{ fontSize: 12, color: 'var(--gg-text-3)', maxWidth: 360, marginTop: 4, lineHeight: 1.5 }}>
            {message}
          </p>
        )}
      </div>

      {actionLabel && onAction && (
        <button
          onClick={onAction}
          className="gg-glass-btn gg-glass-btn-primary"
          style={{ marginTop: 6 }}
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}

export function LoadingState({ message = 'Analyzing Telemetry…' }: { message?: string }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      padding: '48px 24px', gap: 14,
    }}>
      <div style={{
        width: 32, height: 32,
        border: '2px solid rgba(255, 255, 255, 0.08)',
        borderTop: '2px solid #22d3ee',
        borderRadius: '50%',
        animation: 'spin 0.7s linear infinite',
        boxShadow: '0 0 16px rgba(6, 182, 212, 0.3)',
      }} />
      <p style={{ fontSize: 12, color: 'var(--gg-text-2)', fontWeight: 500, fontFamily: 'var(--font-mono)' }}>
        {message}
      </p>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
