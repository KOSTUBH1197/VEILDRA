from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from scapy.all import sniff, IP
from collections import defaultdict
import threading
import time

class VEILDRACore:
    def __init__(self):
        self.net = None
        self.topology_version = 1
        self.packet_counts = defaultdict(list)
        self.scan_threshold = 100
        self.time_window = 10
        self.reshaping = False
        
    def analyze_packet(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            current_time = time.time()
            self.packet_counts[src_ip].append(current_time)
            self.packet_counts[src_ip] = [
                t for t in self.packet_counts[src_ip]
                if current_time - t < self.time_window
            ]
            count = len(self.packet_counts[src_ip])
            if count > self.scan_threshold and not self.reshaping:
                print(f"\n[VEILDRA ALERT] Threat detected from {src_ip} - {count} packets")
                self.reshape_topology()
                
    def reshape_topology(self):
        self.reshaping = True
        self.topology_version += 1
        print(f"[VEILDRA] TOPOLOGY RESHAPING - Version {self.topology_version}")
        
        h1 = self.net.get('h1')
        h2 = self.net.get('h2')
        h3 = self.net.get('h3')
        
        v = self.topology_version
        h1.cmd(f'ip addr flush dev h1-eth0')
        h2.cmd(f'ip addr flush dev h2-eth0')
        h3.cmd(f'ip addr flush dev h3-eth0')
        
        h1.cmd(f'ip addr add 10.0.{v}.1/24 dev h1-eth0')
        h2.cmd(f'ip addr add 10.0.{v}.2/24 dev h2-eth0')
        h3.cmd(f'ip addr add 10.0.{v}.3/24 dev h3-eth0')
        
        print(f"[VEILDRA] Real hosts moved to 10.0.{v}.x")
        print(f"[VEILDRA] Decoys remain at old addresses")
        print(f"[VEILDRA] Attacker map is now INVALID")
        
        self.packet_counts.clear()
        time.sleep(30)
        self.reshaping = False
        
    def start_sniffing(self):
        print("[VEILDRA] Packet monitoring started...")
        sniff(prn=self.analyze_packet, store=0)
        
    def build_and_start(self):
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
        
        print("[VEILDRA] Network ready")
        print("[VEILDRA] Real hosts: h1=10.0.0.1, h2=10.0.0.2, h3=10.0.0.3")
        print("[VEILDRA] Decoys: decoy1=10.0.0.100, decoy2=10.0.0.101")
        print("[VEILDRA] Connectivity test...")
        self.net.pingAll()
        
        sniff_thread = threading.Thread(
            target=self.start_sniffing,
            daemon=True
        )
        sniff_thread.start()
        
        print("\n[VEILDRA] SYSTEM FULLY OPERATIONAL")
        print("[VEILDRA] Try: h2 nmap -sS 10.0.0.1")
        print("[VEILDRA] Watch topology reshape automatically!\n")
        
        CLI(self.net)
        self.net.stop()

if __name__ == "__main__":
    core = VEILDRACore()
    core.build_and_start()
