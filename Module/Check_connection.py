from scapy.all import *

dhcp_result = None

def check_dhcp(pkt):
    global dhcp_result
    if pkt[DHCP].options[0][1] == 5: # if DHCP pkt is ack pkt
        if {pkt[IP].dst} != '255.255.255.255':
            dhcp_result = f"{pkt[Ether].dst} {pkt[IP].dst}"

def sniff_dhcp(interface):
    sniff(prn=check_dhcp, iface=interface, filter="udp and (port 67 or 68)", store=0, count=2)

def check_connection(interface):
    global dhcp_result
    dhcp_result = None
    while(dhcp_result == None):
        sniff_dhcp(interface)
    return dhcp_result

if __name__ == "__main__":
    while(True):
        print(check_connection())