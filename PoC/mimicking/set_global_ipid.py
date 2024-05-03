from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.inet import IP

ipid = 65000 # 16 bit, between 0 and (2^16)-1

def modify_ipid_and_accept(packet):
    pkt = IP(packet.get_payload())

    if IP in pkt:
        global ipid # use global counter
        pkt[IP].id = ipid
        if not pkt[IP].flags == "MF":
            ipid = (ipid + 1) % 65536 # increment
            print('incremented IP ID')
        del pkt[IP].chksum # enforce recalculation of checksum
        packet.set_payload(bytes(pkt))

    packet.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(1, modify_ipid_and_accept)
try:
    print('waiting for data ...')
    nfqueue.run()
except KeyboardInterrupt:
    print('interrupt')

nfqueue.unbind()