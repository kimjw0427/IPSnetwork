from scapy.all import*
import sys

conf.iface = '802.11n USB Wireless LAN Card'

while(1):
    send(IP(dst="127.0.0.1") / ICMP() / 'Whereisnpcap')