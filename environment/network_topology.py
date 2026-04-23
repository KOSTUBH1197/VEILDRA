from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import threading
import time
import sys
sys.path.append('/home/kostubh/veildra')
from agents.traffic_detector import TrafficDetector

class VEILDRANetwork:
    def __init__(self):
        self.net = None
        self.detector = TrafficDetector()
        self.topology_version = 1
        self.alert_count = 0
        
    def build_network(self):
        setLogLevel('info')
        self.net = Mininet(controller=Controller, switch=OVSSwitch)
        
        print("[VEILDRA] Building initial network topology...")
        
        # Add controller
        c0 = self.net.addController('c0')
        
        # Add switches
        s1 = self.net.addSwitch('s1')
        s2 = self.net.addSwitch('s2')
        
        # Add real hosts
        h1 = self.net.addHost('h1', ip='10.0.0.1')
        h2 = self.net.addHost('h2', ip='10.0.0.2')
        h3 = self.net.addHost('h3', ip='10.0.0.3')
        
        # Add decoy hosts (shadow topology)
        decoy1 = self.net.addHost('decoy1', ip='10.0.0.100')
        decoy2 = self.net.addHost('decoy2', ip='10.0.0.101')
        
        # Add links
        self.net.addLink(h1, s1)
        self.net.addLink(h2, s1)
        self.net.addLink(s1, s2)
        self.net.addLink(h3, s2)
        self.net.addLink(decoy1, s2)
        self.net.addLink(decoy2, s2)
        
        print("[VEILDRA] Network topology built successfully")
        print("[VEILDRA] Real hosts: h1, h2, h3")
        print("[VEILDRA] Decoy hosts: decoy1, decoy2")
        return self.net
    
    def reshape_topology(self):
        self.topology_version += 1
        self.alert_count += 1
        print(f"\n[VEILDRA] TOPOLOGY RESHAPING INITIATED - Version {self.topology_version}")
        print(f"[VEILDRA] Moving real hosts to new addresses...")
        
        h1 = self.net.get('h1')
        h2 = self.net.get('h2')
        h3 = self.net.get('h3')
        
        # Assign new IPs to real hosts
        new_ip_h1 = f"10.0.{self.topology_version}.1"
        new_ip_h2 = f"10.0.{self.topology_version}.2"
        new_ip_h3 = f"10.0.{self.topology_version}.3"
        
        h1.cmd(f'ifconfig h1-eth0 {new_ip_h1}')
        h2.cmd(f'ifconfig h2-eth0 {new_ip_h2}')
        h3.cmd(f'ifconfig h3-eth0 {new_ip_h3}')
        
        print(f"[VEILDRA] Real hosts moved to 10.0.{self.topology_version}.x subnet")
        print(f"[VEILDRA] Decoy hosts remain at old addresses to trap attacker")
        print(f"[VEILDRA] Attacker's map is now INVALID")
        
    def monitor_and_respond(self):
        print("[VEILDRA] Starting threat monitoring...")
        while True:
            threats = self.detector.get_threat_report()
            if len(threats) > 0:
                print(f"\n[VEILDRA] {len(threats)} threats detected. Initiating reshape...")
                self.reshape_topology()
                self.detector.suspicious_ips.clear()
            time.sleep(10)
    
    def start(self):
        self.build_network()
        self.net.start()
        
        print("\n[VEILDRA] Starting network...")
        print("[VEILDRA] Testing connectivity...")
        self.net.pingAll()
        
        # Start monitoring in background thread
        monitor_thread = threading.Thread(
            target=self.monitor_and_respond,
            daemon=True
        )
        monitor_thread.start()
        
        print("\n[VEILDRA] System fully operational")
        print("[VEILDRA] Monitoring for threats...")
        CLI(self.net)
        self.net.stop()

if __name__ == "__main__":
    veildra = VEILDRANetwork()
    veildra.start()
