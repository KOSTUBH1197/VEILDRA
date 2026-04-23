# VEILDRA
## Intent-Aware Topological Deception for Proactive Network Defense

**Author:** Kostubh Kumar  
**Type:** Cybersecurity Research Prototype  
**Status:** Active Development

---

## What is VEILDRA?

VEILDRA is a novel network defense system that reads attacker intent in real time and automatically reshapes network topology to invalidate reconnaissance. Unlike traditional honeypots or Moving Target Defense systems, VEILDRA does not wait for attackers to find fake assets. It infers what the attacker is looking for and places convincing decoys exactly where they are about to look.

---

## Four Layer Architecture

**L1 — Behavioral Threat Inference Agent**  
Monitors network traffic in real time and detects reconnaissance using packet rate analysis and behavioral pattern recognition. Achieves sub-10ms detection latency.

**L2 — Topological Restructuring Engine**  
Upon threat detection, automatically moves real hosts to new subnets and migrates services. Every reshape invalidates the attacker's current network map.

**L3 — Cognitive Signature Engine**  
Builds a unique behavioral fingerprint for each attacker based on scan speed, port sequence patterns, and packet characteristics. Re-identifies returning attackers across sessions even when they change IP addresses.

**L4 — Personalized Shadow Topology**  
Infers attacker intent from port scan patterns and deploys tailored decoy services matching exactly what the attacker is searching for.

---

## Intent Classification

| Intent | Trigger Ports | Decoy Deployed |
|--------|--------------|----------------|
| database_hunting | 3306, 5432, 27017, 6379, 1433 | Fake database services |
| web_hunting | 80, 443, 8080, 8443, 8000 | Fake web servers |
| admin_hunting | 22, 23, 3389, 5900 | Fake SSH/RDP services |
| broad_recon | 50+ ports | Generic decoys |

---

## Experimental Results

| Metric | Value |
|--------|-------|
| Avg Detection Time | ~5ms |
| Avg Reshape Time | ~230ms |
| True Positive Rate | 100% |
| False Positive Rate | 0% |
| Returning Attacker Detection | Working |
| Intent Classification Accuracy | 3/3 intents correctly identified |

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
    ├── veildra_main.py              # Main system — all 4 layers integrated
    ├── agents/
    │   ├── traffic_detector.py      # L1 — Threat detection
    │   └── cognitive_signature.py   # L3 — Attacker fingerprinting
    ├── environment/
    │   ├── network_topology.py      # Network setup
    │   └── veildra_core.py          # Core loop
    ├── data/
    │   └── results.json             # Experiment results
    └── test_capture.py              # Packet capture testing

---

## How to Run

### Prerequisites
```bash
sudo apt-get install -y mininet python3-pip nmap
pip3 install scapy scikit-learn pandas numpy matplotlib --break-system-packages
```

### Run VEILDRA
```bash
cd ~/veildra
sudo mn -c
sudo python3 veildra_main.py
```

### Simulate Attacks in Mininet CLI
```bash
# Database hunting
h2 nmap -sS --min-rate 5000 -p 3306,5432,27017,6379,1433,1521,3306,5432,3306,5432,27017,6379 10.0.0.1

# Web server hunting
h2 nmap -sS --min-rate 5000 -p 80,443,8080,8443,8000,3000,80,443,80,443,8080,8443,8000,3000,80 10.0.0.1

# Admin access hunting
h2 nmap -sS --min-rate 5000 -p 22,23,3389,5900,5901,5902,22,23,3389 10.0.0.1
```

---

## Key Novelty

No existing system combines all three of the following:

1. **Threat-aware restructuring** — topology changes triggered by behavioral inference, not fixed timers
2. **Personalized deception** — shadow topology tailored to each attacker's inferred objective
3. **Cross-session re-identification** — returning attackers recognized from behavioral fingerprint alone

---

## Research Paper

Currently in progress. Target venue: IEEE Security and Privacy / NDSS Symposium.

**Title:** VEILDRA: Intent-Aware Topological Deception for Proactive Network Defense

**Key Contributions:**
1. Behavioral inference driven topological restructuring
2. Personalized dynamic shadow topology generation
3. Cross-session attacker re-identification via behavioral fingerprinting

---

## Related Work

This work builds upon and extends Moving Target Defense (Jajodia et al., 2011), SDN-based network deception, dynamic honeypot systems, and attacker behavioral fingerprinting. Sengupta et al. (IEEE Communications Surveys and Tutorials, 2020) identified AI-driven behavioral MTD as an open research direction. VEILDRA directly addresses this gap.
