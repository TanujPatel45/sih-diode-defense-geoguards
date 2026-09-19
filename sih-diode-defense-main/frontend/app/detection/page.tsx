import { TopBar } from '../components/TopBar';

function Pillar({
  title, badge, badgeColor, subtitle, items, note
}: {
  title: string; badge: string; badgeColor: string; subtitle: string;
  items: string[]; note?: string;
}) {
  return (
    <div className="gg-card" style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--gg-text)' }}>{title}</h3>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '3px 9px', borderRadius: 6,
            border: `1px solid ${badgeColor}44`, color: badgeColor, background: `${badgeColor}15`,
            boxShadow: `0 0 10px ${badgeColor}22`,
            letterSpacing: '0.06em', textTransform: 'uppercase' as const,
          }}>{badge}</span>
        </div>
        <p style={{ fontSize: 12, color: 'var(--gg-text-3)' }}>{subtitle}</p>
      </div>
      <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 7 }}>
        {items.map((item, i) => (
          <li key={i} style={{ display: 'flex', gap: 9, fontSize: 12, color: 'var(--gg-text-2)' }}>
            <span style={{ color: '#34d399', flexShrink: 0 }}>✓</span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
      {note && <p style={{ fontSize: 10, color: 'var(--gg-muted)', fontStyle: 'italic', marginTop: 'auto' }}>{note}</p>}
    </div>
  );
}

function FusionWeights() {
  const weights = [
    { label: 'Supervised Classifier', pct: 50, color: '#22d3ee', desc: 'DiodeThreatNet confidence' },
    { label: 'Anomaly Detector',       pct: 25, color: '#fbbf24', desc: 'Isolation Forest score' },
    { label: 'Behaviour Analytics',    pct: 25, color: '#fb923c', desc: 'Statistical heuristic score' },
  ];
  return (
    <div className="gg-card" style={{ padding: 24 }}>
      <div style={{ marginBottom: 18 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--gg-text)' }}>Risk Fusion Engine</h3>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '3px 9px', borderRadius: 6,
            border: '1px solid rgba(245,158,11,0.4)', color: '#fbbf24',
            background: 'rgba(245,158,11,0.12)', boxShadow: '0 0 10px rgba(245,158,11,0.2)',
            letterSpacing: '0.06em', textTransform: 'uppercase' as const,
          }}>Consensus Architecture</span>
        </div>
        <p style={{ fontSize: 12, color: 'var(--gg-text-3)' }}>
          Combines all three detection pillar scores into a single fused risk score [0–1].
          Weights represent calibrated baseline multi-model consensus fusion.
        </p>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {weights.map((w) => (
          <div key={w.label}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12, marginBottom: 6 }}>
              <span style={{ color: 'var(--gg-text)', fontWeight: 600 }}>{w.label}</span>
              <div style={{ display: 'flex', gap: 12, fontSize: 11 }}>
                <span style={{ color: 'var(--gg-text-3)' }}>{w.desc}</span>
                <span style={{ color: w.color, fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{w.pct}%</span>
              </div>
            </div>
            <div style={{
              height: 6,
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.05)',
              borderRadius: 3,
              overflow: 'hidden',
            }}>
              <div style={{
                height: '100%',
                width: `${w.pct}%`,
                background: `linear-gradient(90deg, ${w.color}88, ${w.color})`,
                boxShadow: `0 0 10px ${w.color}66`,
                borderRadius: 3
              }} />
            </div>
          </div>
        ))}
      </div>
      <div style={{
        marginTop: 18,
        padding: 14,
        background: 'rgba(255, 255, 255, 0.025)',
        border: '1px solid var(--gg-border)',
        borderRadius: 'var(--gg-radius-sm)',
        fontSize: 11,
        color: 'var(--gg-text-3)'
      }}>
        <strong style={{ color: 'var(--gg-cyan)', fontFamily: 'var(--font-mono)' }}>Formula: </strong>
        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>
          final_risk = (0.50 × classifier_score) + (0.25 × anomaly_score) + (0.25 × behaviour_score)
        </span>
      </div>
    </div>
  );
}

function ThreatCoverage() {
  const categories = [
    {
      name: 'Volumetric / Protocol DDoS',
      status: 'VALIDATED',
      dataset: 'CIC-IDS2017 (DDoS / PortScan / LOIC)',
      color: '#ef4444',
      signals: 'SYN flag ratio (≥0.80), packet rate (>500 pps), uniform small packet distribution, UDP datagram bursts.',
      method: 'Supervised MLP (DiodeThreatNet) + Specialized DDoS Engine'
    },
    {
      name: 'Botnet C2 Beaconing',
      status: 'VALIDATED',
      dataset: 'CIC-IDS2017 (Infiltration / Botnet)',
      color: '#fb923c',
      signals: 'Inter-arrival timing regularity (IAT CV < 0.25), mean interval 0.5s–120s, small keepalive payloads, low timing jitter.',
      method: 'Behaviour Analytics + Specialized Periodic C2 Engine'
    },
    {
      name: 'DGA Domains & DNS Tunnelling',
      status: 'VALIDATED',
      dataset: 'Real DGA & DNS-Tunnel Benchmark',
      color: '#22d3ee',
      signals: 'High payload Shannon entropy (≥6.8 bits), inflated DNS query lengths (>30 chars), high query frequencies, char n-gram TF-IDF.',
      method: 'DGA TF-IDF Classifier + Shannon Entropy Heuristic'
    },
    {
      name: 'Reconnaissance / Port Scanning',
      status: 'IMPLEMENTED',
      dataset: 'Passive Flow Metadata Evaluation',
      color: '#a855f7',
      signals: 'Short probe flows (1–4 packets), high SYN probe ratio without established payload, elevated TCP RST flags (>0.40).',
      method: 'Specialized Recon Engine + Statistical Heuristics'
    },
    {
      name: 'Data Exfiltration',
      status: 'IMPLEMENTED',
      dataset: 'Passive Flow Metadata Evaluation',
      color: '#ec4899',
      signals: 'Unilateral byte asymmetry (outbound/inbound ratio ≥4:1), sustained volume (>200 KB), high entropy outbound archives.',
      method: 'Specialized Exfiltration Engine + Asymmetry Heuristics'
    },
    {
      name: 'Malware in Encrypted Sessions',
      status: 'IMPLEMENTED',
      dataset: 'Metadata-Only (Zero Decryption)',
      color: '#3b82f6',
      signals: 'Strictly passive: TLS/QUIC session entropy (≥7.5 bits), low packet length variance in stream (std < 25), SNI string entropy.',
      method: 'Metadata Sequence Analyzer (No Payload Decryption)'
    },
  ];

  return (
    <div className="gg-card" style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--gg-text)' }}>
            PS 26145 Supported Threat Taxonomy & Validation Status
          </h3>
          <p style={{ fontSize: 12, color: 'var(--gg-text-3)', marginTop: 2 }}>
            Covers the complete 6-class threat taxonomy using passive observable metadata without active probing or decryption.
          </p>
        </div>
        <span style={{
          fontSize: 10, fontWeight: 700, padding: '3px 9px', borderRadius: 6,
          border: '1px solid rgba(16,185,129,0.4)', color: '#34d399', background: 'rgba(16,185,129,0.12)',
          letterSpacing: '0.06em', textTransform: 'uppercase'
        }}>
          6 / 6 THREAT CLASSES ACTIVE
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
        {categories.map((cat) => (
          <div key={cat.name} style={{
            padding: 14,
            borderRadius: 'var(--gg-radius-sm)',
            background: 'rgba(255, 255, 255, 0.02)',
            border: '1px solid var(--gg-border)',
            display: 'flex',
            flexDirection: 'column',
            gap: 6
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: cat.color }}>
                {cat.name}
              </span>
              <span style={{
                fontSize: 9,
                fontWeight: 800,
                fontFamily: 'var(--font-mono)',
                padding: '2px 6px',
                borderRadius: 4,
                background: cat.status === 'VALIDATED' ? 'rgba(16,185,129,0.15)' : 'rgba(56,189,248,0.15)',
                border: `1px solid ${cat.status === 'VALIDATED' ? 'rgba(16,185,129,0.4)' : 'rgba(56,189,248,0.4)'}`,
                color: cat.status === 'VALIDATED' ? '#34d399' : '#38bdf8'
              }}>
                {cat.status}
              </span>
            </div>

            <div style={{ fontSize: 11, color: 'var(--gg-text-2)', lineHeight: 1.4 }}>
              <strong>Signals: </strong>{cat.signals}
            </div>

            <div style={{ fontSize: 10, color: 'var(--gg-text-3)', fontFamily: 'var(--font-mono)', marginTop: 'auto', paddingTop: 4 }}>
              Baseline: {cat.dataset} · Engine: {cat.method}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ImplVsFuture() {
  const impl = [
    'PCAP flow extraction (Scapy PcapReader)', '5-tuple flow tracking',
    '21 extracted flow features', 'PyTorch classifier (DiodeThreatNet)',
    'Isolation Forest anomaly detection (Real Benign baseline)', 'Behaviour analytics (statistical heuristics)',
    '6-class specialized detection engines', 'Correlation engine & Attack Stories',
    'Continuous operations & parallel traffic monitoring', 'Risk fusion engine',
    'Explainable alerts (Evidence + Why)', 'Next.js SOC dashboard',
  ];
  const future = [
    'Physical optical data-diode hardware integration', 'Expanded continuous retraining pipeline',
    'Hardware ASIC / FPGA line-rate packet parsing', 'Cross-site federated threat sharing',
    'Automated honeynet calibration',
  ];
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
      <div className="gg-card" style={{ padding: 24 }}>
        <p className="gg-label" style={{ color: '#34d399', marginBottom: 14 }}>✓ Implemented & Verified System</p>
        <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 6 }}>
          {impl.map((item, i) => (
            <li key={i} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--gg-text-2)' }}>
              <span style={{ color: '#34d399', flexShrink: 0 }}>✓</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="gg-card" style={{ padding: 24 }}>
        <p className="gg-label" style={{ color: '#22d3ee', marginBottom: 14 }}>→ Production Roadmap</p>
        <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 6 }}>
          {future.map((item, i) => (
            <li key={i} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--gg-text-3)' }}>
              <span style={{ color: '#22d3ee', flexShrink: 0 }}>→</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default function DetectionEngine() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100%' }}>
      <TopBar
        title="Detection Engine"
        subtitle="3-Pillar passive multi-model consensus architecture · Explainability and risk fusion"
      />

      <div style={{ flex: 1, padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Pillars */}
        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
          <Pillar
            title="1. Supervised Classifier"
            badge="PyTorch MLP"
            badgeColor="#22d3ee"
            subtitle="DiodeThreatNet — Multi-class neural network"
            items={[
              '21 extracted flow metadata features',
              'Classification: Benign, Flood, DNS Tunneling, C2 Beaconing',
              'Outputs class probability distribution',
              'Sub-millisecond inference per flow',
            ]}
            note="Trained on baseline synthetic attack traffic."
          />
          <Pillar
            title="2. Anomaly Detection"
            badge="Isolation Forest"
            badgeColor="#fbbf24"
            subtitle="Unsupervised outlier & deviation detection"
            items={[
              'No attack signature dependency',
              'Detects statistical outliers in feature space',
              'Normalized anomaly score [0–1]',
              'Flags novel and zero-day threat patterns',
            ]}
            note="Unsupervised model for zero-day identification."
          />
          <Pillar
            title="3. Behaviour Analytics"
            badge="Heuristic Engine"
            badgeColor="#fb923c"
            subtitle="Domain-specific network traffic heuristic rules"
            items={[
              'Beacon regularity / jitter analysis',
              'High-frequency UDP / DNS payload ratio',
              'Port scan & sweep pattern matching',
              'Data exfiltration volume heuristics',
            ]}
            note="Domain expert heuristics for passive metadata."
          />
        </section>

        {/* Fusion */}
        <FusionWeights />

        {/* 6-Threat PS Taxonomy */}
        <ThreatCoverage />

        {/* Status */}
        <ImplVsFuture />
      </div>
    </div>
  );
}
