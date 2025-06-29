from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

print("Starting packet capture... (Ctrl+C to stop)")
sniff(prn=packet_callback, count=10)