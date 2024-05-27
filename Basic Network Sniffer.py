from scapy.all import sniff

def p_handler(pkt):
    print(pkt.summary())

sniff(prn=p_handler, count=10) 
def p_handler(pkt):
    if pkt.haslayer(IP):
        ip_layer = pkt.getlayer(IP)
        print(f"Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst}")
        print(pkt.show())
packets = sniff(count=100)
packets.summary()
packets[0].show()