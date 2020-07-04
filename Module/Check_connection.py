from scapy.all import *
import time
import threading


conf.iface = 'Microsoft Hosted Network Virtual Adapter'

dhcp_result = None

def check_dhcp(pkt):
    global dhcp_result
    if pkt[DHCP].options[0][1] == 5: # if DHCP pkt is ack pkt
        if {pkt[IP].dst} != '255.255.255.255':
            dhcp_result = f"{pkt[Ether].dst} {pkt[IP].dst}"

def sniff_dhcp():
    sniff(prn=check_dhcp, filter="udp and (port 67 or 68)", store=0, count=2)

def check_connection():
    global dhcp_result
    dhcp_result = None
    while(dhcp_result == None):
        sniff_dhcp()
    return dhcp_result

if __name__ == "__main__":
    while(True):
        print(check_connection())