import json
import time
import hashlib
from collections import defaultdict

class CognitiveSignatureEngine:
    def __init__(self):
        self.attacker_profiles = {}
        self.signature_db = {}
        self.alert_log = []
        
    def extract_signature(self, ip, packet_times, port_sequence):
        if len(packet_times) < 2:
            return None
            
        intervals = []
        for i in range(1, len(packet_times)):
            intervals.append(packet_times[i] - packet_times[i-1])
            
        signature = {
            "avg_interval": sum(intervals) / len(intervals),
            "min_interval": min(intervals),
            "max_interval": max(intervals),
            "packet_count": len(packet_times),
            "port_sequence_hash": hashlib.md5(
                str(port_sequence[:10]).encode()
            ).hexdigest()[:8],
            "scan_speed": len(packet_times) / (
                packet_times[-1] - packet_times[0] + 0.001
            )
        }
        return signature
    
    def register_attacker(self, ip, signature):
        sig_key = f"{signature['port_sequence_hash']}_{round(signature['scan_speed'], 1)}"
        
        if sig_key in self.signature_db:
            existing = self.signature_db[sig_key]
            print(f"\n[VEILDRA] RETURNING ATTACKER DETECTED!")
            print(f"[VEILDRA] Current IP: {ip}")
            print(f"[VEILDRA] Previously seen as: {existing['ip']}")
            print(f"[VEILDRA] First seen: {existing['first_seen']}")
            print(f"[VEILDRA] Times detected: {existing['count']}")
            print(f"[VEILDRA] Activating enhanced defenses...")
            self.signature_db[sig_key]['count'] += 1
            self.signature_db[sig_key]['last_ip'] = ip
            return True
        else:
            self.signature_db[sig_key] = {
                "ip": ip,
                "signature": signature,
                "first_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
                "count": 1,
                "last_ip": ip
            }
            print(f"\n[VEILDRA] New attacker fingerprinted: {ip}")
            print(f"[VEILDRA] Signature ID: {sig_key}")
            print(f"[VEILDRA] Scan speed: {round(signature['scan_speed'], 2)} packets/sec")
            return False
    
    def get_all_profiles(self):
        return self.signature_db
    
    def save_profiles(self):
        with open('/home/kostubh/veildra/data/attacker_profiles.json', 'w') as f:
            json.dump(self.signature_db, f, indent=2)
        print("[VEILDRA] Attacker profiles saved to data/attacker_profiles.json")

if __name__ == "__main__":
    engine = CognitiveSignatureEngine()
    
    print("[VEILDRA] Cognitive Signature Engine initialized")
    print("[VEILDRA] Simulating attacker fingerprinting...\n")
    
    # Simulate attacker 1
    times1 = [time.time() + i*0.1 for i in range(20)]
    ports1 = [22, 80, 443, 8080, 3306, 21, 25, 53, 110, 143]
    sig1 = engine.extract_signature("192.168.1.100", times1, ports1)
    engine.register_attacker("192.168.1.100", sig1)
    
    time.sleep(1)
    
    # Simulate same attacker returning with different IP
    times2 = [time.time() + i*0.1 for i in range(20)]
    ports2 = [22, 80, 443, 8080, 3306, 21, 25, 53, 110, 143]
    sig2 = engine.extract_signature("10.10.10.50", times2, ports2)
    engine.register_attacker("10.10.10.50", sig2)
    
    time.sleep(1)
    
    # Simulate different attacker
    times3 = [time.time() + i*0.5 for i in range(20)]
    ports3 = [3389, 445, 139, 135, 1433, 5432, 6379, 27017, 9200, 5601]
    sig3 = engine.extract_signature("172.16.0.55", times3, ports3)
    engine.register_attacker("172.16.0.55", sig3)
    
    engine.save_profiles()
    
    print(f"\n[VEILDRA] Total attackers in database: {len(engine.signature_db)}")
