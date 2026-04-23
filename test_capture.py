from scapy.all import sniff, IP, TCP, Raw

packet_count = 0
port_samples = []

def analyze(packet):
    global packet_count
    if packet.haslayer(IP) and packet.haslayer(TCP):
        packet_count += 1
        src_ip = packet[IP].src
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        
        if packet_count <= 30:
            print(f"Packet {packet_count}: {src_ip} sport={sport} dport={dport} flags={flags}")
            port_samples.append((sport, dport))
        
        if packet_count == 30:
            print("\n=== ANALYSIS ===")
            dports = [p[1] for p in port_samples]
            sports = [p[0] for p in port_samples]
            print(f"Unique dports: {set(dports)}")
            print(f"Unique sports: {set(sports)}")

print("Capturing 30 packets on lo interface...")
print("Now run in Mininet: h2 nmap -sS -p 3306,5432,22,80 10.0.0.1")
sniff(iface="lo", prn=analyze, store=0, count=30)
