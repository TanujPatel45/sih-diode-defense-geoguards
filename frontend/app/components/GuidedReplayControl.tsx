'use client';

import { useState, useEffect, useCallback } from 'react';
import { API } from '../lib/api';
import { Play, Pause, RotateCcw, GitCommit, CheckCircle2 } from 'lucide-react';

const STAGES = [
  { stage: 'Stage 1', key: 'recon', name: 'Reconnaissance / Port Scanning', description: 'Nmap TCP SYN scan discovering open services', color: '#a855f7' },
  { stage: 'Stage 2', key: 'c2',    name: 'Botnet C2 Beaconing',           description: 'Periodic heartbeat beaconing to C2 IP 91.195.240.117', color: '#fb923c' },
  { stage: 'Stage 3', key: 'dns',   name: 'DGA Domains & DNS Tunnelling',  description: 'Base64 encoded DNS query exfiltration chunking', color: '#22d3ee' },
  { stage: 'Stage 4', key: 'exfil', name: 'Data Exfiltration',            description: 'High-volume HTTP/S outbound payload transfer', color: '#ec4899' },
];

export function GuidedReplayControl({ onRefresh }: { onRefresh?: () => void }) {
  const [running, setRunning] = useState(false);
  const [paused, setPaused]   = useState(false);
  const [statusMsg, setStatusMsg] = useState('Idle · Ready to launch Guided Multi-Stage Attack Replay');
  const [activeStage, setActiveStage] = useState<string>('');
  const [completedStages, setCompletedStages] = useState<string[]>([]);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await API.attackReplayStatus() as {
        status?: string;
        state?: string;
        current_stage?: string;
        stages_completed?: string[];
        packets_processed?: number;
        alerts_emitted?: number;
      };
      if (res) {
        const stateStr = (res.state || res.status || 'IDLE').toUpperCase();
        const isRun = stateStr === 'RUNNING';
        const isPause = stateStr === 'PAUSED';
        const isComp = stateStr === 'COMPLETED';

        setRunning(isRun);
        setPaused(isPause);

        if (res.current_stage) setActiveStage(res.current_stage);
        if (Array.isArray(res.stages_completed)) setCompletedStages(res.stages_completed);

        if (isComp) {
          setStatusMsg('✓ Multi-Stage Replay Complete: All 4 stages executed & correlated into Attack Story incident.');
          onRefresh?.();
        } else if (isRun) {
          setStatusMsg(`Replaying attack stream: Current Stage = "${res.current_stage || 'Processing'}" (${res.packets_processed || 0} packets)...`);
          onRefresh?.();
        } else if (isPause) {
          setStatusMsg('Replay PAUSED by operator.');
        } else if (stateStr === 'IDLE' && completedStages.length === 0) {
          setStatusMsg('Idle · Ready to launch Guided Multi-Stage Attack Replay');
        }
      }
    } catch {
      // offline
    }
  }, [onRefresh, completedStages.length]);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 1000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  const handleStart = async () => {
    try {
      setRunning(true);
      setStatusMsg('Starting Guided Multi-Stage Attack Replay PCAP stream...');
      await API.attackReplayStart('Multi-Stage Exfiltration', 0.0);
      await fetchStatus();
      onRefresh?.();
    } catch (err) {
      setStatusMsg(`Error starting replay: ${err instanceof Error ? err.message : String(err)}`);
      setRunning(false);
    }
  };

  const handlePause = async () => {
    try {
      await API.attackReplayPause();
      setPaused(true);
      setRunning(false);
      setStatusMsg('Replay PAUSED by operator.');
    } catch { /* ignore */ }
  };

  const handleResume = async () => {
    try {
      await API.attackReplayResume();
      setPaused(false);
      setRunning(true);
      setStatusMsg('Replay RESUMED.');
    } catch { /* ignore */ }
  };

  const handleReset = async () => {
    try {
      await API.attackReplayReset();
      setRunning(false);
      setPaused(false);
      setActiveStage('');
      setCompletedStages([]);
      setStatusMsg('Replay session reset. Correlation state cleared.');
      onRefresh?.();
    } catch { /* ignore */ }
  };

  const isStageDone = (key: string) => {
    if (completedStages.some((s) => s.toLowerCase().includes(key))) return true;
    if (statusMsg.includes('Complete') || activeStage.includes('Completed')) return true;
    return false;
  };

  const isStageCurrent = (key: string) => {
    return activeStage.toLowerCase().includes(key);
  };

  return (
    <div className="gg-card" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <GitCommit size={18} color="#a855f7" />
            <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--gg-text)', margin: 0 }}>
              Guided Multi-Stage Attack Replay
            </h3>
            <span style={{
              fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
              border: '1px solid rgba(168,85,247,0.4)', color: '#c084fc',
              background: 'rgba(168,85,247,0.12)', textTransform: 'uppercase', letterSpacing: '0.06em'
            }}>
              PCAP Stream Engine
            </span>
          </div>
          <p style={{ fontSize: 12, color: 'var(--gg-muted)', marginTop: 4, marginBottom: 0 }}>
            Replays authentic multi-stage PCAP traffic (Recon → C2 → DNS Tunnel → Exfiltration) through the real detection pipeline into 1 correlated incident story.
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {!running && !paused ? (
            <button
              onClick={handleStart}
              className="gg-glass-btn gg-glass-btn-primary"
              style={{
                padding: '8px 16px', fontSize: 12, fontWeight: 700,
                background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.25), rgba(6, 182, 212, 0.2))',
                border: '1px solid rgba(168, 85, 247, 0.4)',
              }}
            >
              <Play size={14} /> Launch Multi-Stage Replay
            </button>
          ) : running ? (
            <button
              onClick={handlePause}
              className="gg-glass-btn"
              style={{ padding: '8px 14px', fontSize: 12, fontWeight: 600, color: '#fbbf24', border: '1px solid rgba(251, 191, 36, 0.4)' }}
            >
              <Pause size={14} /> Pause
            </button>
          ) : (
            <button
              onClick={handleResume}
              className="gg-glass-btn gg-glass-btn-primary"
              style={{ padding: '8px 14px', fontSize: 12, fontWeight: 600 }}
            >
              <Play size={14} /> Resume
            </button>
          )}

          <button
            onClick={handleReset}
            className="gg-glass-btn"
            style={{ padding: '8px 12px', fontSize: 12, color: 'var(--gg-text-3)' }}
            title="Reset replay session"
          >
            <RotateCcw size={14} /> Reset
          </button>
        </div>
      </div>

      {/* 4-Stage Lifecycle Stepper */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
        {STAGES.map((s, idx) => {
          const isDone = isStageDone(s.key);
          const isActive = isStageCurrent(s.key);

          return (
            <div
              key={s.stage}
              style={{
                padding: '12px 14px',
                borderRadius: 'var(--gg-radius-sm)',
                border: `1px solid ${isActive ? s.color : isDone ? 'rgba(16, 185, 129, 0.3)' : 'var(--gg-border)'}`,
                background: isActive ? `${s.color}15` : isDone ? 'rgba(16, 185, 129, 0.05)' : 'rgba(255, 255, 255, 0.02)',
                display: 'flex',
                flexDirection: 'column',
                gap: 6,
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 10, fontWeight: 800, color: s.color, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                  {s.stage}
                </span>
                {isDone ? (
                  <CheckCircle2 size={13} color="#34d399" />
                ) : isActive ? (
                  <span className="status-dot status-dot-cyan animate-pulse-dot" />
                ) : (
                  <span style={{ fontSize: 9, color: 'var(--gg-muted)' }}>{idx + 1}</span>
                )}
              </div>
              <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--gg-text)', lineHeight: 1.2 }}>
                {s.name}
              </div>
              <div style={{ fontSize: 10, color: 'var(--gg-text-3)', lineHeight: 1.3 }}>
                {s.description}
              </div>
            </div>
          );
        })}
      </div>

      {/* Status Bar */}
      <div style={{
        padding: '8px 12px',
        borderRadius: 6,
        background: 'rgba(255,255,255,0.02)',
        border: '1px solid var(--gg-border)',
        fontSize: 11,
        fontFamily: 'var(--font-mono)',
        color: 'var(--gg-text-2)',
        display: 'flex',
        alignItems: 'center',
        gap: 8
      }}>
        <span style={{ color: 'var(--gg-cyan)' }}>[Status]</span>
        <span>{statusMsg}</span>
      </div>
    </div>
  );
}
