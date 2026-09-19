/**
 * api.ts — Centralized API client for GeoGuards SOC Dashboard (SIH 26145)
 */

import type { Alert, Stats, HealthStatus, PcapAnalysisResult, CorrelationCluster, StreamingReplayResponse, StreamingTelemetry } from './types';

function getBaseUrl(): string {
  if (typeof window !== 'undefined') {
    if (process.env.NEXT_PUBLIC_API_BASE_URL) {
      return process.env.NEXT_PUBLIC_API_BASE_URL.replace(/\/$/, '');
    }
    // In browser, default to direct backend endpoint
    return 'http://127.0.0.1:8000';
  }
  return (process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://127.0.0.1:8000').replace(/\/$/, '');
}

const BASE = getBaseUrl();

async function apiFetch<T>(path: string, init?: RequestInit, timeoutMs = 5000): Promise<T> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${BASE}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json', ...init?.headers },
    });
    clearTimeout(timeoutId);
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new Error(`API ${res.status}: ${text}`);
    }
    return res.json() as Promise<T>;
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}

export const API = {
  health: ()                   => apiFetch<HealthStatus>('/api/v1/health', undefined, 5000),
  stats:  ()                   => apiFetch<Stats>('/api/v1/stats', undefined, 5000),
  alerts: (limit = 100)        => apiFetch<Alert[]>(`/api/v1/alerts?limit=${limit}`, undefined, 5000),
  flows:  (limit = 100)        => apiFetch<Alert[]>(`/api/v1/flows?limit=${limit}`, undefined, 5000),
  alert:  (id: string)         => apiFetch<Alert>(`/api/v1/alerts/${id}`, undefined, 5000),
  correlationClusters: ()      => apiFetch<CorrelationCluster[]>('/api/v1/correlation/clusters', undefined, 5000),
  benchmarkSummary: ()         => apiFetch<Record<string, unknown>>('/api/v1/benchmark/summary', undefined, 5000),

  analyzeFlow: (flow: Record<string, unknown>) =>
    apiFetch<Alert>('/api/v1/analyze-flow', {
      method: 'POST',
      body: JSON.stringify(flow),
    }, 4000),

  streamPcap: async (
    file: File,
    speed = 0.0,
    onProgress?: (progress: { packets: number; bytes: number; flows: number; alerts: number; elapsed: number }) => void,
    onAlert?: (alert: Alert) => void,
    onComplete?: (telemetry: StreamingTelemetry) => void
  ): Promise<StreamingReplayResponse> => {
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch(`${BASE}/api/v1/stream-pcap?speed=${speed}`, { method: 'POST', body: fd });
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new Error(`API ${res.status}: ${text}`);
    }

    const reader = res.body?.getReader();
    if (!reader) throw new Error('ReadableStream is not supported in this browser environment.');

    const decoder = new TextDecoder();
    let buffer = '';
    const alertsList: Alert[] = [];
    let totalAlertsCount = 0;
    let telemetryResult: StreamingTelemetry | null = null;
    let completeMessage = 'PCAP stream replay completed.';
    let receivedComplete = false;

    // Helper: parse one SSE block and update state
    function processBlock(block: string) {
      const trimmed = block.trim();
      if (!trimmed.startsWith('data:')) return;
      const jsonStr = trimmed.slice(5).trim();
      if (!jsonStr) return;

      let evt: Record<string, unknown>;
      try {
        evt = JSON.parse(jsonStr);
      } catch {
        return; // ignore malformed SSE lines
      }

      if (evt.type === 'progress') {
        onProgress?.({
          packets: (evt.packets_processed as number) ?? 0,
          bytes:   (evt.bytes_processed   as number) ?? 0,
          flows:   (evt.flows_processed   as number) ?? 0,
          alerts:  (evt.alerts_emitted    as number) ?? 0,
          elapsed: (evt.elapsed_time_sec  as number) ?? 0,
        });
      } else if (evt.type === 'alert' && evt.alert) {
        const a = evt.alert as Alert;
        totalAlertsCount++;
        if (alertsList.length < 500) {
          alertsList.unshift(a);
        }
        onAlert?.(a);
      } else if (evt.type === 'complete') {
        receivedComplete = true;
        telemetryResult = evt.telemetry as StreamingTelemetry;
        if (evt.message) completeMessage = evt.message as string;
        onComplete?.(telemetryResult);
      } else if (evt.type === 'error') {
        // Backend sent an explicit error event — turn it into a thrown Error
        const pkts = evt.packets_processed != null
          ? ` (after ${evt.packets_processed} packets)`
          : '';
        throw new Error(
          `Backend error${pkts}: ${(evt.message as string) || 'Unknown streaming error'}`
        );
      }
    }

    while (true) {
      const { done, value } = await reader.read();

      if (done) {
        // Stream closed — try to drain any remaining buffer first
        if (buffer.trim()) {
          const finalBlocks = buffer.split('\n\n');
          for (const block of finalBlocks) {
            try { processBlock(block); } catch { /* already threw above if backend error */ }
          }
        }
        // If we never got a 'complete' event, the backend disconnected unexpectedly
        if (!receivedComplete) {
          throw new Error(
            `Backend disconnected mid-stream after processing ${alertsList.length} alert(s). ` +
            `The PCAP may be too large or the server encountered an internal error. ` +
            `Check backend logs for details.`
          );
        }
        break;
      }

      buffer += decoder.decode(value, { stream: true });
      const blocks = buffer.split('\n\n');
      buffer = blocks.pop() ?? '';

      for (const block of blocks) {
        processBlock(block); // throws on backend error events
      }
    }

    const finalTelemetry = telemetryResult as StreamingTelemetry | null;
    const totalEmitted = finalTelemetry?.alerts_emitted ?? totalAlertsCount;
    return {
      message: completeMessage,
      telemetry: finalTelemetry ?? {
        status: 'COMPLETED',
        packets_processed: 0,
        bytes_processed: 0,
        flows_processed: 0,
        alerts_emitted: totalEmitted,
        elapsed_time_sec: 0,
        flows_per_second: 0,
        throughput_mbps: 0,
        avg_inference_latency_ms: 0,
        p50_inference_latency_ms: 0,
        p95_inference_latency_ms: 0,
      },
      total_alerts: totalEmitted,
      returned_alerts: alertsList.length,
      alerts_truncated: totalEmitted > alertsList.length,
      alerts_count: totalEmitted,
      alerts: alertsList,
    };
  },

  analyzePcap: async (file: File): Promise<PcapAnalysisResult> => {
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch(`${BASE}/api/v1/analyze-pcap`, { method: 'POST', body: fd });
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new Error(`API ${res.status}: ${text}`);
    }
    return res.json();
  },

  attackReplayStart: (scenario = 'Multi-Stage Exfiltration', speed = 0.0) =>
    apiFetch<Record<string, unknown>>('/api/v1/attack-replay/start', {
      method: 'POST',
      body: JSON.stringify({ scenario_name: scenario, speed }),
    }, 5000),

  attackReplayPause: () =>
    apiFetch<Record<string, unknown>>('/api/v1/attack-replay/pause', { method: 'POST' }, 5000),

  attackReplayResume: () =>
    apiFetch<Record<string, unknown>>('/api/v1/attack-replay/resume', { method: 'POST' }, 5000),

  attackReplayReset: () =>
    apiFetch<Record<string, unknown>>('/api/v1/attack-replay/reset', { method: 'POST' }, 5000),

  attackReplayStatus: () =>
    apiFetch<Record<string, unknown>>('/api/v1/attack-replay/status', undefined, 5000),

  attackReplayTimeline: () =>
    apiFetch<TimelineEvent[]>('/api/v1/attack-replay/timeline', undefined, 5000),

  attackReplayIncident: () =>
    apiFetch<CorrelationCluster | null>('/api/v1/attack-replay/incident', undefined, 5000),
};

export { BASE };
