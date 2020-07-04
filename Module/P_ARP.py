from scapy.all import *
import time
import threading


conf.iface = 'Microsoft Hosted Network Virtual Adapter'

def arp_send(src, hwsrc, dst):
    send(ARP(op=2, pdst=src, hwdst=hwsrc, psrc=dst), verbose=False)
    time.sleep(1)
    send(ARP(op=2, pdst=src, hwdst=hwsrc, psrc=dst), verbose=False)
    time.sleep(1)
    send(ARP(op=2, pdst=src, hwdst=hwsrc, psrc=dst), verbose=False)


def arp_block(pkt):
    if pkt[ARP].op == 1:
        if pkt[ARP].hwsrc != get_if_hwaddr(conf.iface):
            arp_thread = threading.Thread(target=arp_send, args=(pkt[ARP].psrc, pkt[ARP].hwsrc, pkt[ARP].pdst))
            arp_thread.start()


def prevention_arp():
    sniff(prn=arp_block, filter="arp", store=0, count=1)

if __name__ == "__main__":
    while(True):
        prevention_arp()