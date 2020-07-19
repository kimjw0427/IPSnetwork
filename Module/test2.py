
from scapy.all import *

print(conf.iface)
conf.iface.setmonitor(True)

sendp(PrismHeader()/
          Dot11(addr1="ff:ff:ff:ff:ff:ff",
                addr2=get_if_hwaddr(conf.iface),
                addr3=get_if_hwaddr(conf.iface))/
          Dot11Beacon(cap="ESS", timestamp=1)/
          Dot11Elt(ID="SSID", info=RandString(RandNum(1,50)))/
          Dot11EltRates(rates=[130, 132, 11, 22])/
          Dot11Elt(ID="DSset", info="\x03")/
          Dot11Elt(ID="TIM", info="\x00\x01\x00\x00"), loop=1)