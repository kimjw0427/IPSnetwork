from scapy.all import *

conf.iface = '802.11n USB Wireless LAN Card'

def eap_sniff(pkt):
	print(pkt[EAPOL].type)


sniff(prn=eap_sniff, filter='ether proto 0x888e', monitor=True)
