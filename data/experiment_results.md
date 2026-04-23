# VEILDRA Experiment Results
**Date:** April 23, 2026  
**Environment:** Ubuntu 24.04 on VirtualBox, Mininet simulation  
**Tester:** Kostubh Kumar

---

## Experiment 1 — Threat Detection Accuracy

| Scan Type | Packets Sent | Detected | Detection Time |
|-----------|-------------|----------|----------------|
| Database scan | 9 packets | YES | 2.89ms |
| Web scan | 9 packets | YES | 8.18ms |
| Admin scan | 9 packets | YES | 1.45ms |

**True Positive Rate: 100%**  
**False Positive Rate: 0%**

---

## Experiment 2 — Intent Classification

| Attack Intent | Ports Scanned | Correctly Classified |
|--------------|--------------|---------------------|
| database_hunting | 3306, 5432, 27017, 6379, 1433 | YES |
| web_hunting | 80, 443, 8080, 8443, 8000 | YES |
| admin_hunting | 22, 23, 3389, 5900 | YES |

**Intent Classification Accuracy: 3/3 (100%)**

---

## Experiment 3 — Topology Reshaping Performance

| Metric | Value |
|--------|-------|
| Avg Reshape Time | 228ms |
| Min Reshape Time | 145ms |
| Max Reshape Time | 651ms |
| Topology Versions Created | 3+ per session |

---

## Experiment 4 — Returning Attacker Detection

| Session | IP Used | Detected as Returning |
|---------|---------|----------------------|
| Session 1 | 127.0.0.1 | New attacker registered |
| Session 2 | 127.0.0.1 | RETURNING ATTACKER DETECTED |
| Times detected | 2 | Match confidence: HIGH |

**Re-identification Accuracy: 100% in controlled test**

---

## Experiment 5 — System Performance

| Metric | Value |
|--------|-------|
| Avg Detection Time | 4.67ms |
| Min Detection Time | 0.59ms |
| Max Detection Time | 32.3ms |
| Avg Packet Size (scan) | 58 bytes |
| Scan Speed Detected | 221 to 2517 packets/sec |

---

## Summary

VEILDRA successfully demonstrated:
1. Real-time threat detection under 10ms average
2. 100% intent classification accuracy across 3 attack types
3. Automatic topology reshaping under 250ms average
4. Returning attacker re-identification across sessions
5. Zero false positives during testing
