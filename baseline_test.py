from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import time

def baseline_network():
    setLogLevel('warning')
    net = Mininet(controller=Controller, switch=OVSSwitch)
    
    c0 = net.addController('c0')
    s1 = net.addSwitch('s1')
    
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    h3 = net.addHost('h3', ip='10.0.0.3')
    
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    
    net.start()
    
    print("=" * 50)
    print("BASELINE — Static Network (No Defense)")
    print("=" * 50)
    print("Hosts: h1=10.0.0.1, h2=10.0.0.2, h3=10.0.0.3")
    print("NO detection system active")
    print("NO topology reshaping")
    print("NO deception layer")
    print("Attacker can map network freely")
    print("=" * 50)
    print("Try: h2 nmap -sS --min-rate 5000 -p 3306,5432,27017,6379,1433,1521,3306,5432,3306,5432,27017,6379 10.0.0.1")
    print("Observe: No detection, no response, network remains static")
    
    CLI(net)
    net.stop()

if __name__ == "__main__":
    baseline_network()
