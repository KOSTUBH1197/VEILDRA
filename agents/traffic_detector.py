import scapy.all as scapy
from collections import defaultdict
import time
import json
import os

class TrafficDetector:
    def __init__(self):
        self.scan_threshold = 10
        self.time_window = 60
        self.suspicious_ips = {}
        self.packet_counts = defaultdict(list)
        
    def analyze_packet(self, packet):
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            current_time = time.time()
            
            self.packet_counts[src_ip].append(current_time)
            
            # Remove old packets outside time window
            self.packet_counts[src_ip] = [
                t for t in self.packet_counts[src_ip]
                if current_time - t < self.time_window
            ]
            
            count = len(self.packet_counts[src_ip])
            
            if count > self.scan_threshold:
                self.log_suspicious(src_ip, count)
                return True
        return False
    
    def log_suspicious(self, ip, count):
        self.suspicious_ips[ip] = {
            "ip": ip,
            "packet_count": count,
            "timestamp": time.time(),
            "threat_level": "HIGH" if count > 50 else "MEDIUM"
        }
        print(f"[VEILDRA ALERT] Suspicious activity from {ip} - {count} packets detected")
        
    def get_threat_report(self):
        return self.suspicious_ips

if __name__ == "__main__":
    detector = TrafficDetector()
    print("[VEILDRA] Traffic Detector initialized")
    print("[VEILDRA] Starting network monitoring...")
    scapy.sniff(prn=detector.analyze_packet, store=0)
