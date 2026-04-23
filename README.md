# VEILDRA
## Intent-Aware Topological Deception for Proactive Network Defense

**Author:** Kostubh Kumar and Dr. Hemamalini V.
**Type:** Cybersecurity Research Prototype  
**Status:** Active Development

---

## What is VEILDRA?

VEILDRA is a novel network defense system that reads attacker intent in real time and automatically reshapes network topology to invalidate reconnaissance, while deploying personalized deception environments tailored to each attacker's objectives.

Unlike traditional honeypots or Moving Target Defense systems, VEILDRA does not wait for attackers to find fake assets. It infers what the attacker is looking for and places convincing decoys exactly where they are about to look.

---

## Four Layer Architecture

### L1 — Behavioral Threat Inference Agent
Monitors network traffic in real time and detects reconnaissance behavior using packet rate analysis and behavioral pattern recognition. Distinguishes between normal traffic and active scanning with sub-10ms detection latency.

### L2 — Topological Restructuring Engine
Upon threat detection, automatically moves real hosts to new subnets and migrates services without disrupting legitimate operations. Every reshape invalidates the attacker's current network map.

### L3 — Cognitive Signature Engine
Builds a unique behavioral fingerprint for each attacker based on scan speed, port sequence patterns, and packet characteristics. Re-identifies returning attackers across sessions even when they change IP addresses.

### L4 — Personalized Shadow Topology
Infers attacker intent (database hunting, web hunting, admin hunting, broad recon) from port scan patterns and deploys tailored decoy services that match exactly what the attacker is searching for.

---

## Experimental Results

| Metric | Value |
|--------|-------|
| Avg Detection Time | ~5ms |
| Avg Reshape Time | ~230ms |
| True Positive Rate | 100% |
| False Positive Rate | 0% |
| Intent Classification | admin, web, database, broad recon |
| Returning Attacker Detection | Working |

---

## Tech Stack

- Python 3.12
- Mininet (Network Simulation)
- POX SDN Controller
- Scapy (Packet Analysis)
- Scikit-learn
- Open vSwitch

---

## Project Structure
# VEILDRA
## Intent-Aware Topological Deception for Proactive Network Defense

**Author:** Kostubh Kumar  
**Type:** Cybersecurity Research Prototype  
**Status:** Active Development

---

## What is VEILDRA?

VEILDRA is a novel network defense system that reads attacker intent in real time and automatically reshapes network topology to invalidate reconnaissance, while deploying personalized deception environments tailored to each attacker's objectives.

Unlike traditional honeypots or Moving Target Defense systems, VEILDRA does not wait for attackers to find fake assets. It infers what the attacker is looking for and places convincing decoys exactly where they are about to look.

---

## Four Layer Architecture

### L1 — Behavioral Threat Inference Agent
Monitors network traffic in real time and detects reconnaissance behavior using packet rate analysis and behavioral pattern recognition. Distinguishes between normal traffic and active scanning with sub-10ms detection latency.

### L2 — Topological Restructuring Engine
Upon threat detection, automatically moves real hosts to new subnets and migrates services without disrupting legitimate operations. Every reshape invalidates the attacker's current network map.

### L3 — Cognitive Signature Engine
Builds a unique behavioral fingerprint for each attacker based on scan speed, port sequence patterns, and packet characteristics. Re-identifies returning attackers across sessions even when they change IP addresses.

### L4 — Personalized Shadow Topology
Infers attacker intent (database hunting, web hunting, admin hunting, broad recon) from port scan patterns and deploys tailored decoy services that match exactly what the attacker is searching for.

---

## Experimental Results

| Metric | Value |
|--------|-------|
| Avg Detection Time | ~5ms |
| Avg Reshape Time | ~230ms |
| True Positive Rate | 100% |
| False Positive Rate | 0% |
| Intent Classification | admin, web, database, broad recon |
| Returning Attacker Detection | Working |

---

## Tech Stack

- Python 3.12
- Mininet (Network Simulation)
- POX SDN Controller
- Scapy (Packet Analysis)
- Scikit-learn
- Open vSwitch

---

## Project Structure
# VEILDRA
## Intent-Aware Topological Deception for Proactive Network Defense

**Author:** Kostubh Kumar  
**Type:** Cybersecurity Research Prototype  
**Status:** Active Development

---

## What is VEILDRA?

VEILDRA is a novel network defense system that reads attacker intent in real time and automatically reshapes network topology to invalidate reconnaissance, while deploying personalized deception environments tailored to each attacker's objectives.

Unlike traditional honeypots or Moving Target Defense systems, VEILDRA does not wait for attackers to find fake assets. It infers what the attacker is looking for and places convincing decoys exactly where they are about to look.

---

## Four Layer Architecture

### L1 — Behavioral Threat Inference Agent
Monitors network traffic in real time and detects reconnaissance behavior using packet rate analysis and behavioral pattern recognition. Distinguishes between normal traffic and active scanning with sub-10ms detection latency.

### L2 — Topological Restructuring Engine
Upon threat detection, automatically moves real hosts to new subnets and migrates services without disrupting legitimate operations. Every reshape invalidates the attacker's current network map.

### L3 — Cognitive Signature Engine
Builds a unique behavioral fingerprint for each attacker based on scan speed, port sequence patterns, and packet characteristics. Re-identifies returning attackers across sessions even when they change IP addresses.

### L4 — Personalized Shadow Topology
Infers attacker intent (database hunting, web hunting, admin hunting, broad recon) from port scan patterns and deploys tailored decoy services that match exactly what the attacker is searching for.

---

## Experimental Results

| Metric | Value |
|--------|-------|
| Avg Detection Time | ~5ms |
| Avg Reshape Time | ~230ms |
| True Positive Rate | 100% |
| False Positive Rate | 0% |
| Intent Classification | admin, web, database, broad recon |
| Returning Attacker Detection | Working |

---

## Tech Stack

- Python 3.12
- Mininet (Network Simulation)
- POX SDN Controller
- Scapy (Packet Analysis)
- Scikit-learn
- Open vSwitch

---

## Project Structure
veildra/
├── veildra_main.py          # Main system - all 4 layers integrated
├── agents/
│   ├── traffic_detector.py  # L1 - Threat detection
│   └── cognitive_signature.py # L3 - Attacker fingerprinting
├── environment/
│   ├── network_topology.py  # Network setup
│   └── veildra_core.py      # Core loop
├── data/
│   └── results.json         # Experiment results
└── test_capture.py          # Packet capture testing

---

## How to Run

### Prerequisites
```bash
sudo apt-get install -y mininet python3-pip
pip3 install scapy scikit-learn pandas numpy matplotlib --break-system-packages
```

### Run VEILDRA
```bash
cd ~/veildra
sudo python3 veildra_main.py
```

### Simulate Attacks in Mininet CLI
```bash
# Database hunting scan
h2 nmap -sS --min-rate 5000 -p 3306,5432,27017,6379,1433 10.0.0.1

# Web server hunting scan  
h2 nmap -sS --min-rate 5000 -p 80,443,8080,8443,8000 10.0.0.1

# Admin access hunting scan
h2 nmap -sS --min-rate 5000 -p 22,23,3389,5900 10.0.0.1
```

---

## Research Paper

Research paper currently in progress. To be submitted to IEEE Security and Privacy / NDSS Symposium.

**Title:** VEILDRA: Intent-Aware Topological Deception for Proactive Network Defense

**Key Contributions:**
1. Threat-aware topological restructuring driven by behavioral inference rather than fixed timers
2. Personalized dynamic shadow topology generation based on inferred attacker intent
3. Cross-session attacker re-identification using behavioral fingerprinting

---

## Novelty

No existing system combines:
- Real-time attacker intent inference
- Topology restructuring triggered by behavioral detection
- Personalized deception tailored to attacker objectives
- Cross-session behavioral re-identification

This combination represents a new paradigm in proactive network defense.

---

## Related Work

This work builds upon and extends:
- Moving Target Defense (Jajodia et al., 2011)
- SDN-based network deception
- Attacker behavioral fingerprinting
- Dynamic honeypot systems

**Sengupta et al. (IEEE Communications Surveys & Tutorials, 2020)** identified AI-driven behavioral MTD as an open research direction. VEILDRA directly addresses this gap.
