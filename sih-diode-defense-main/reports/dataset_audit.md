# GeoGuards Dataset Audit Report

**Audit Timestamp:** 2026-09-10T13:01:57.059615

**Problem Statement:** SIH 26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

## 1. Executive Summary

| Dataset | Format | Files | Size (MB) | Samples / Records | Primary Role |
|---|---|---|---|---|---|
| **CIC-IDS2017** | CSV (Flows) | 8 | 843.7 MB | 2,830,743 | Primary Supervised Training & Baseline Anomaly |
| **DGA Domains** | CSV (Domains) | 2 | 19.0 MB | 674,898 | DNS DGA Domain Intelligence Component |
| **DNS-Tunnel** | PCAP (Raw) | 131 | 844.3 MB | 131 PCAP captures | Dedicated DNS Tunnel Detector & Robustness |
| **USTC-TFC2016** | PCAP/7z | 20 | 369.2 MB | 20 Classes (10 Benign / 10 Malware) | External Malware Generalization |
| **CTU-13 / Botnet** | CSV/Flows | 1 | - | 1,966 Botnet Flows | C2 Beaconing & Periodicity Validation |

## 2. Detailed Dataset Breakdown

### 2.1 CIC-IDS2017 (Canadian Institute for Cybersecurity)
- **Path:** `datasets/MachineLearningCSV/MachineLearningCVE/`
- **Total Flow Samples:** 2,830,743
- **Features:** 79 bi-directional network flow attributes (Flow Duration, IAT, Packet Lengths, Flags, Subflow Bytes, etc.)
- **Label Distribution:**
  - `BENIGN`: 2,273,097 (80.30%)
  - `DoS Hulk`: 231,073 (8.16%)
  - `PortScan`: 158,930 (5.61%)
  - `DDoS`: 128,027 (4.52%)
  - `DoS GoldenEye`: 10,293 (0.36%)
  - `FTP-Patator`: 7,938 (0.28%)
  - `SSH-Patator`: 5,897 (0.21%)
  - `DoS slowloris`: 5,796 (0.20%)
  - `DoS Slowhttptest`: 5,499 (0.19%)
  - `Bot`: 1,966 (0.07%)
  - `Web Attack ï¿½ Brute Force`: 1,507 (0.05%)
  - `Web Attack ï¿½ XSS`: 652 (0.02%)
  - `Infiltration`: 36 (0.00%)
  - `Web Attack ï¿½ Sql Injection`: 21 (0.00%)
  - `Heartbleed`: 11 (0.00%)

**Files in CIC-IDS2017:**
- **Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv** (73.55 MB, 225,745 rows)
  - DDoS: 128,027
  - BENIGN: 97,718
- **Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv** (73.34 MB, 286,467 rows)
  - PortScan: 158,930
  - BENIGN: 127,537
- **Friday-WorkingHours-Morning.pcap_ISCX.csv** (55.62 MB, 191,033 rows)
  - BENIGN: 189,067
  - Bot: 1,966
- **Monday-WorkingHours.pcap_ISCX.csv** (168.73 MB, 529,918 rows)
  - BENIGN: 529,918
- **Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv** (79.25 MB, 288,602 rows)
  - BENIGN: 288,566
  - Infiltration: 36
- **Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv** (49.61 MB, 170,366 rows)
  - BENIGN: 168,186
  - Web Attack ï¿½ Brute Force: 1,507
  - Web Attack ï¿½ XSS: 652
  - Web Attack ï¿½ Sql Injection: 21
- **Tuesday-WorkingHours.pcap_ISCX.csv** (128.82 MB, 445,909 rows)
  - BENIGN: 432,074
  - FTP-Patator: 7,938
  - SSH-Patator: 5,897
- **Wednesday-workingHours.pcap_ISCX.csv** (214.74 MB, 692,703 rows)
  - BENIGN: 440,031
  - DoS Hulk: 231,073
  - DoS GoldenEye: 10,293
  - DoS slowloris: 5,796
  - DoS Slowhttptest: 5,499
  - Heartbleed: 11

### 2.2 DGA Domains Dataset
- **Path:** `datasets/DGA_domains_dataset-master/`
- **Total Domain Strings:** 674,898
- **Class Balance:**
  - `dga`: 337,500 (50.01%)
  - `legit`: 337,398 (49.99%)
- **Malware Families (26):** Alexa (legit: 337,398), gozi, corebot, ranbyus, symmi, emotet, dircrypt, matsnu, simda, fobber...

### 2.3 DNS-Tunnel-Datasets
- **Path:** `datasets/DNS-Tunnel-Datasets-main/`
- **Total PCAP Files:** 131
- **Categories:**
  - **crossEndPoint**: 9 PCAP files (112.07 MB)
  - **normal**: 68 PCAP files (232.43 MB)
  - **tunnel**: 24 PCAP files (191.46 MB)
  - **unkownTunnel**: 17 PCAP files (160.08 MB)
  - **wildcard**: 13 PCAP files (148.31 MB)

### 2.4 USTC-TFC2016
- **Path:** `datasets/USTC-TFC2016-master/`
- **Benign Classes:** BitTorrent.pcap, Facetime.pcap, FTP.pcap, Gmail.pcap, MySQL.pcap, Outlook.pcap, Skype.pcap, SMB.7z, Weibo.7z, WorldOfWarcraft.pcap
- **Malware Classes:** Cridex.7z, Geodo.7z, Htbot.7z, Miuref.pcap, Neris.7z, Nsis-ay.7z, Shifu.7z, Tinba.pcap, Virut.7z, Zeus.pcap

## 3. Data Leakage Prevention & Split Strategy
1. **Session & Day Isolation:** Train, validation, and test splits are partitioned by capture session and temporal block to prevent leaking flows from the same TCP connection or attack burst.
2. **Dedicated Benign Baseline:** The Isolation Forest anomaly detector is fit **exclusively on clean Monday/Tuesday benign traffic**, strictly excluding attack records.
3. **Zero-Day DNS Tunnel Holdout:** `unkownTunnel`, `wildcard`, and `crossEndPoint` partitions are strictly held out for robustness testing and never seen during DNS model tuning.
4. **DGA Family-Aware Holdout:** Evaluation tests generalization on unseen DGA algorithm families.
