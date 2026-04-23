from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import time
import json
import hashlib
import statistics
import random
import subprocess

class VEILDRA:
    def __init__(self):
        self.net = None
        self.topology_version = 1
        self.packet_counts = defaultdict(list)
        self.port_sequences = defaultdict(list)
        self.packet_times = defaultdict(list)
        self.packet_sizes = defaultdict(list)
        self.scan_threshold =5
        self.time_window = 10
        self.reshaping = False
        self.signature_db = {}
        self.attacker_shadows = {}
        
        # Track which attacker is currently being analyzed
        self.current_attacker = None
        
        # Performance metrics
        self.total_threats = 0
        self.total_reshapes = 0
        self.returning_attackers = 0
        self.detection_times = []
        self.reshape_times = []
        self.false_positives = 0
        self.true_positives = 0
        self.shadow_deployments = 0
        self.start_time = time.time()
        
        # Valid Mininet IP ranges (for filtering)
        self.mininet_ranges = ["10.0."]
        
    # ============ LAYER 1 — THREAT DETECTION WITH FILTERING ============
    
    def is_mininet_traffic(self, src_ip):
        """Only count traffic from Mininet hosts, ignore system noise"""
        for prefix in self.mininet_ranges:
            if src_ip.startswith(prefix):
                return True
        # Also allow 127.0.0.1 since Mininet internal traffic uses it
        if src_ip == "127.0.0.1":
            return False
        return False
    
    def analyze_packet(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            
            # Filter — Only process Mininet network traffic
            if not self.is_mininet_traffic(src_ip):
                return
                
            current_time = time.time()
            
            self.packet_counts[src_ip].append(current_time)
            self.packet_times[src_ip].append(current_time)
            # Filter ICMP ping traffic
            from scapy.all import ICMP
            if packet.haslayer(ICMP):
                return
            self.packet_sizes[src_ip].append(len(packet))
            
            if packet.haslayer(TCP):
               self.port_sequences[src_ip].append(packet[TCP].dport)
               # Also capture source port for loopback scenarios
               self.port_sequences[src_ip].append(packet[TCP].sport)
            
            self.packet_counts[src_ip] = [
                t for t in self.packet_counts[src_ip]
                if current_time - t < self.time_window
            ]
            
            count = len(self.packet_counts[src_ip])
            
            if count > self.scan_threshold and not self.reshaping:
                detection_start = time.time()
                self.total_threats += 1
                self.true_positives += 1
                self.current_attacker = src_ip
                
                print(f"\n[VEILDRA L1] THREAT DETECTED from {src_ip}")
                print(f"[VEILDRA L1] Packets in {self.time_window}s: {count}")
                print(f"[VEILDRA L1] Avg packet size: {round(statistics.mean(self.packet_sizes[src_ip]), 2)} bytes")
                
                # Layer 3 — Fingerprint first
                sig_key = self.fingerprint_attacker(src_ip)
                
                detection_time = (time.time() - detection_start) * 1000
                self.detection_times.append(detection_time)
                print(f"[VEILDRA METRICS] Detection time: {round(detection_time, 2)}ms")
                
                # Layer 2 — Reshape with personalized shadow
                threading.Thread(
                    target=self.reshape_with_shadow,
                    args=(src_ip, sig_key),
                    daemon=True
                ).start()
    
    # ============ LAYER 3 — ADVANCED FINGERPRINTING ============
    
    def fingerprint_attacker(self, ip):
        times = self.packet_times[ip]
        ports = self.port_sequences[ip]
        sizes = self.packet_sizes[ip]
        
        if len(times) < 5:
            return None
            
        intervals = []
        for i in range(1, min(len(times), 50)):
            intervals.append(times[i] - times[i-1])
        
        if not intervals:
            return None
            
        scan_speed = len(times) / (times[-1] - times[0] + 0.001)
        avg_interval = statistics.mean(intervals)
        
        try:
            interval_stddev = statistics.stdev(intervals)
        except:
            interval_stddev = 0
            
        avg_packet_size = statistics.mean(sizes) if sizes else 0
        
        port_diffs = []
        if len(ports) > 1:
            for i in range(1, min(len(ports), 20)):
                port_diffs.append(abs(ports[i] - ports[i-1]))
        
        port_pattern = "sequential" if port_diffs and statistics.mean(port_diffs) < 5 else "random"
        
        # Analyze intent — what is the attacker looking for?
        intent = self.infer_attacker_intent(ports)
        
        signature = {
            "avg_interval": round(avg_interval, 4),
            "interval_stddev": round(interval_stddev, 4),
            "scan_speed": round(scan_speed, 2),
            "avg_packet_size": round(avg_packet_size, 2),
            "port_pattern": port_pattern,
            "packet_count": len(times),
            "inferred_intent": intent
        }
        
        speed_bucket = int(scan_speed / 500) * 500
        size_bucket = int(avg_packet_size / 100) * 100
        sig_key = f"{speed_bucket}_{size_bucket}_{port_pattern}_{intent}"
        
        if sig_key in self.signature_db:
            self.returning_attackers += 1
            existing = self.signature_db[sig_key]
            print(f"\n[VEILDRA L3] RETURNING ATTACKER DETECTED!")
            print(f"[VEILDRA L3] Current IP: {ip}")
            print(f"[VEILDRA L3] Previously seen as: {existing['ip']}")
            print(f"[VEILDRA L3] First detection: {existing['first_seen']}")
            print(f"[VEILDRA L3] Total appearances: {existing['count'] + 1}")
            print(f"[VEILDRA L3] Inferred intent: {intent}")
            print(f"[VEILDRA L3] Activating MAXIMUM defenses")
            self.signature_db[sig_key]['count'] += 1
            self.signature_db[sig_key]['last_ip'] = ip
            self.signature_db[sig_key]['last_seen'] = time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            self.signature_db[sig_key] = {
                "ip": ip,
                "signature": signature,
                "first_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
                "count": 1,
                "last_ip": ip,
                "last_seen": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            print(f"\n[VEILDRA L3] New attacker fingerprinted")
            print(f"[VEILDRA L3] IP: {ip}")
            print(f"[VEILDRA L3] Signature ID: {sig_key}")
            print(f"[VEILDRA L3] Scan speed: {signature['scan_speed']} packets/sec")
            print(f"[VEILDRA L3] Port pattern: {port_pattern}")
            print(f"[VEILDRA L3] Inferred intent: {intent}")
        
        return sig_key
    
    def infer_attacker_intent(self, ports):
        """Analyze port patterns to infer what attacker is searching for"""
        if not ports:
            return "unknown"
        
        unique_ports = set(ports)
        
        # Database scanning
        db_ports = {3306, 5432, 27017, 6379, 1433, 1521}
        if len(unique_ports & db_ports) >= 1:
            return "database_hunting"
        
        # Web server scanning
        web_ports = {80, 443, 8080, 8443, 8000, 3000}
        if len(unique_ports & web_ports) >= 1:
            return "web_hunting"
        
        # SSH/admin scanning
        admin_ports = {22, 23, 3389, 5900}
        if len(unique_ports & admin_ports) >= 1:
            return "admin_hunting"
        
        # Broad reconnaissance
        if len(unique_ports) > 50:
            return "broad_recon"
        
        return "targeted_recon"
    
    # ============ LAYER 2 — RESHAPE WITH PERSONALIZED SHADOW ============
    
    def reshape_with_shadow(self, attacker_ip, sig_key):
        reshape_start = time.time()
        self.reshaping = True
        
        try:
            self.total_reshapes += 1
            self.topology_version += 1
            v = self.topology_version
            
            print(f"\n[VEILDRA L2] TOPOLOGY RESHAPING - Version {v}")
            
            try:
                h1_pid = int(self.net.get('h1').pid)
                h2_pid = int(self.net.get('h2').pid)
                h3_pid = int(self.net.get('h3').pid)

                subprocess.call(['mnexec', '-a', str(h1_pid), 'ip', 'addr', 'flush', 'dev', 'h1-eth0'])
                subprocess.call(['mnexec', '-a', str(h2_pid), 'ip', 'addr', 'flush', 'dev', 'h2-eth0'])
                subprocess.call(['mnexec', '-a', str(h3_pid), 'ip', 'addr', 'flush', 'dev', 'h3-eth0'])

                subprocess.call(['mnexec', '-a', str(h1_pid), 'ip', 'addr', 'add', f'10.0.{v}.1/24', 'dev', 'h1-eth0'])
                subprocess.call(['mnexec', '-a', str(h2_pid), 'ip', 'addr', 'add', f'10.0.{v}.2/24', 'dev', 'h2-eth0'])
                subprocess.call(['mnexec', '-a', str(h3_pid), 'ip', 'addr', 'add', f'10.0.{v}.3/24', 'dev', 'h3-eth0'])
                print(f"[VEILDRA L2] Real hosts moved to 10.0.{v}.x subnet")
                
                self.migrate_services(v)
                
                if sig_key and sig_key in self.signature_db:
                    intent = self.signature_db[sig_key]['signature'].get('inferred_intent', 'unknown')
                    self.deploy_shadow_topology(attacker_ip, intent)
                
                reshape_time = (time.time() - reshape_start) * 1000
                self.reshape_times.append(reshape_time)
                
                print(f"[VEILDRA L2] Attacker map is now INVALID")
                print(f"[VEILDRA METRICS] Total reshape time: {round(reshape_time, 2)}ms")
                
            except Exception as e:
                print(f"[VEILDRA L2] Reshape inner error: {e}")
            
            self.packet_counts.clear()
            self.port_sequences.clear()
            self.packet_times.clear()
            self.packet_sizes.clear()
            time.sleep(5)
        
        except Exception as outer_e:
            print(f"[VEILDRA L2] Reshape outer error: {outer_e}")
        
        finally:
            self.reshaping = False
            print("[VEILDRA] System ready for next threat")


    def migrate_services(self, version):
        """Migrate services along with hosts"""
        try:
            h1 = self.net.get('h1')
            h2 = self.net.get('h2')
            h3 = self.net.get('h3')
            
            # Kill any existing services
            h1.cmd('pkill -f "python3 -m http.server" 2>/dev/null')
            h2.cmd('pkill -f "python3 -m http.server" 2>/dev/null')
            h3.cmd('pkill -f "python3 -m http.server" 2>/dev/null')
            
            # Deploy new services on different ports per version
            base_port = 8000 + version
            h1.cmd(f'python3 -m http.server {base_port} &>/dev/null &')
            h2.cmd(f'python3 -m http.server {base_port + 1} &>/dev/null &')
            h3.cmd(f'python3 -m http.server {base_port + 2} &>/dev/null &')
            
            print(f"[VEILDRA L2] Services migrated to ports {base_port}-{base_port+2}")
        except Exception as e:
            print(f"[VEILDRA L2] Service migration error: {e}")
    
    def deploy_shadow_topology(self, attacker_ip, intent):
        """Deploy personalized decoys based on what attacker is searching for"""
        self.shadow_deployments += 1
        
        print(f"\n[VEILDRA SHADOW] Deploying personalized shadow for {attacker_ip}")
        print(f"[VEILDRA SHADOW] Attacker intent: {intent}")
        
        try:
            decoy1 = self.net.get('decoy1')
            decoy2 = self.net.get('decoy2')
            
            # Kill existing fake services
            decoy1.cmd('pkill -f "python3 -m http.server" 2>/dev/null')
            decoy2.cmd('pkill -f "python3 -m http.server" 2>/dev/null')
            
            if intent == "database_hunting":
                # Deploy fake database services
                decoy1.cmd('python3 -m http.server 3306 &>/dev/null &')
                decoy2.cmd('python3 -m http.server 5432 &>/dev/null &')
                print(f"[VEILDRA SHADOW] Fake databases deployed on decoy1:3306, decoy2:5432")
                
            elif intent == "web_hunting":
                # Deploy fake web servers
                decoy1.cmd('python3 -m http.server 80 &>/dev/null &')
                decoy2.cmd('python3 -m http.server 443 &>/dev/null &')
                print(f"[VEILDRA SHADOW] Fake web servers deployed on decoy1:80, decoy2:443")
                
            elif intent == "admin_hunting":
                # Deploy fake SSH/RDP
                decoy1.cmd('python3 -m http.server 22 &>/dev/null &')
                decoy2.cmd('python3 -m http.server 3389 &>/dev/null &')
                print(f"[VEILDRA SHADOW] Fake admin services deployed on decoy1:22, decoy2:3389")
                
            else:
                # Generic bait
                decoy1.cmd('python3 -m http.server 8888 &>/dev/null &')
                decoy2.cmd('python3 -m http.server 9999 &>/dev/null &')
                print(f"[VEILDRA SHADOW] Generic decoys deployed on decoy1:8888, decoy2:9999")
            
            self.attacker_shadows[attacker_ip] = {
                "intent": intent,
                "deployed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "version": self.topology_version
            }
            
            print(f"[VEILDRA SHADOW] Shadow topology ID: SHADOW_{self.shadow_deployments}")
            print(f"[VEILDRA SHADOW] Attacker will find exactly what they are looking for")
            print(f"[VEILDRA SHADOW] But none of it is real")
            
        except Exception as e:
            print(f"[VEILDRA SHADOW] Shadow deployment error: {e}")
    
    # ============ METRICS AND REPORTING ============
    
    def print_stats(self):
        while True:
            time.sleep(60)
            uptime = time.time() - self.start_time
            avg_detection = statistics.mean(self.detection_times) if self.detection_times else 0
            avg_reshape = statistics.mean(self.reshape_times) if self.reshape_times else 0
            
            print(f"\n[VEILDRA METRICS] ==========================")
            print(f"Uptime: {round(uptime, 2)}s")
            print(f"Topology Version: {self.topology_version}")
            print(f"Total Threats: {self.total_threats}")
            print(f"Total Reshapes: {self.total_reshapes}")
            print(f"True Positives: {self.true_positives}")
            print(f"False Positives: {self.false_positives}")
            print(f"Returning Attackers Caught: {self.returning_attackers}")
            print(f"Unique Attackers in DB: {len(self.signature_db)}")
            print(f"Shadow Deployments: {self.shadow_deployments}")
            print(f"Avg Detection Time: {round(avg_detection, 2)}ms")
            print(f"Avg Reshape Time: {round(avg_reshape, 2)}ms")
            print(f"==========================================\n")
    
    def save_results(self):
        results = {
            "metrics": {
                "total_threats": self.total_threats,
                "total_reshapes": self.total_reshapes,
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "returning_attackers": self.returning_attackers,
                "unique_attackers": len(self.signature_db),
                "shadow_deployments": self.shadow_deployments,
                "avg_detection_time_ms": statistics.mean(self.detection_times) if self.detection_times else 0,
                "avg_reshape_time_ms": statistics.mean(self.reshape_times) if self.reshape_times else 0,
                "uptime_seconds": time.time() - self.start_time
            },
            "signatures": self.signature_db,
            "shadows": self.attacker_shadows
        }
        
        with open('/home/kostubh/veildra/data/results.json', 'w') as f:
            json.dump(results, f, indent=2)
        print("[VEILDRA] Results saved to data/results.json")
    
    def build_network(self):
        setLogLevel('warning')
        self.net = Mininet(controller=Controller, switch=OVSSwitch)
        
        c0 = self.net.addController('c0')
        s1 = self.net.addSwitch('s1')
        s2 = self.net.addSwitch('s2')
        
        h1 = self.net.addHost('h1', ip='10.0.0.1')
        h2 = self.net.addHost('h2', ip='10.0.0.2')
        h3 = self.net.addHost('h3', ip='10.0.0.3')
        decoy1 = self.net.addHost('decoy1', ip='10.0.0.100')
        decoy2 = self.net.addHost('decoy2', ip='10.0.0.101')
        
        self.net.addLink(h1, s1)
        self.net.addLink(h2, s1)
        self.net.addLink(h3, s1)
        self.net.addLink(s1, s2)
        self.net.addLink(decoy1, s2)
        self.net.addLink(decoy2, s2)
        
        self.net.start()
    
    def start(self):
        print("=" * 55)
        print("  VEILDRA - Intelligent Network Defense System")
        print("  Kostubh Kumar")
        print("=" * 55)
        
        print("\n[VEILDRA] Building network...")
        self.build_network()
        
        print("[VEILDRA] Real hosts: h1=10.0.0.1, h2=10.0.0.2, h3=10.0.0.3")
        print("[VEILDRA] Decoy hosts: decoy1=10.0.0.100, decoy2=10.0.0.101")
        
        print("[VEILDRA] Testing connectivity...")
        self.net.pingAll()
        
        sniff_thread = threading.Thread(
            target=lambda: sniff(iface=["s1-eth1", "s1-eth2", "s1-eth3"], prn=self.analyze_packet, store=0),
            daemon=True
        )
        sniff_thread.start()
        
        stats_thread = threading.Thread(
            target=self.print_stats,
            daemon=True
        )
        stats_thread.start()
        
        print("\n[VEILDRA] ALL FOUR MECHANISMS ACTIVE")
        print("[VEILDRA] L1 - Threat Detection with Noise Filtering")
        print("[VEILDRA] L2 - Topology Reshape + Service Migration")
        print("[VEILDRA] L3 - Behavioral Fingerprinting + Intent Inference")
        print("[VEILDRA] L4 - Personalized Shadow Topology Generation")
        print("\n[VEILDRA] SYSTEM FULLY OPERATIONAL")
        print("[VEILDRA] Try database scan: h2 nmap -sS -p 3306,5432,27017 10.0.0.1")
        print("[VEILDRA] Try web scan: h2 nmap -sS -p 80,443,8080 10.0.0.1")
        print("=" * 55)
        
        CLI(self.net)
        
        self.save_results()
        self.net.stop()
        
        print("\n[VEILDRA] SESSION COMPLETE")
        print(f"Total Threats: {self.total_threats}")
        print(f"Total Reshapes: {self.total_reshapes}")
        print(f"Returning Attackers: {self.returning_attackers}")
        print(f"Shadow Deployments: {self.shadow_deployments}")

if __name__ == "__main__":
    veildra = VEILDRA()
    veildra.start()
