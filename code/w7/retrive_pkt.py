#!/usr/bin/python3

from scapy.all import *
import sys

class DataField(Packet):
    name = "DataField "
    fields_desc = [BitField(name="field_1", default=1, size=128)]



def retrivePacket(src, dst, payload):
    pkt = Ether()
    pkt.src = src
    pkt.dst = dst
    pkt.type = 0x700
    d = DataField()
    
    packet = pkt/d
    return packet

def main():
    _, src, dst, payload = sys.argv
    print(src, dst, payload)
    packet = retrivePacket(src, dst, payload)
    sendp(packet, iface='eth0')
    packet.show()

if __name__=="__main__":
        main()
