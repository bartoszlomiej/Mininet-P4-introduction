#!/usr/bin/python3

from p4runtime_sh.shell import *
import os
print(os.getcwd())

setup(device_id=0, grpc_addr="localhost:9559", election_id=(0, 1), config=FwdPipeConfig("p4info.txt", "build/solution.json"))

def clear_mac_addr(c):
    s = c.hex()
    mac = ""
    for i in range(0, len(s)-1, 2):
        for j in range(i,i+2):
            mac+=s[j]
        mac += ":"
    if mac[-1] == ":":
        mac = mac[:len(mac)-1]
    octets = len(mac)
    print(mac, octets)
    while octets < 17:
        octets += 3
        mac = "00:" + mac

    return mac

#digest list creation
d = digest_entry["mac_learn_t"]
d.ack_timeout_ns=1000000000
d.max_timeout_ns=1000000000
d.max_list_size=100
d.insert()

while True:
    try:
        de = digest_list.digest_list_queue.get() #proceed if digest is found
        a = de.digest.data[0]
        b = a.struct
        c = b.members[0].bitstring
        mac = clear_mac_addr(c)
        port = b.members[1].bitstring[0]
        ipv4 = b.members[2].bitstring
    
        te = TableEntry("cIngress.learned_MAC")(action="NoAction")
        te.match["srcAddr"] = mac
        te.insert()

        tab2 = TableEntry("cIngress.l2_table")(action="mac_forward")
        if mac == "00:04:00:00:00:00":
            tab2.match["dstAddr"] = "10.0.0.10"
        elif mac == "00:04:00:00:00:01":
            tab2.match["dstAddr"] = "10.0.1.10"        
        tab2.action["dstAddr"] = mac
        tab2.action["port"] = str(port)

        tab2.insert()
    except:
        print("entry was duplicated")
