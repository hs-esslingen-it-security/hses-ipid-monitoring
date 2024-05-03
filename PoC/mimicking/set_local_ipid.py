# mimic local IP-ID assignment on LD
from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.inet import IP
from secrets import randbelow
import hashlib

# prepare counter table to store linear offset for IP ID per stream
n = 65536 # counter table size
counter = [0] * n
# init random counters
for i in range(n):
    counter[i] = randbelow(n)


def modify_ipid_and_accept(packet):
    global counter
    pkt = IP(packet.get_payload())

    if IP in pkt:
        # IP ID unique for src&dst&proto combination -> pkt[IP].src, pkt[IP].dst, pkt[IP].proto
        s = str(pkt[IP].src) + str(pkt[IP].dst) + str(pkt[IP].proto) # concat
        hash_index = int(hashlib.md5(s.encode('utf8')).hexdigest(),16) % n

        ipid = (hash_index + counter[hash_index]) % n # IP ID value will be the result of a random offset plus a linear function
        pkt[IP].id = ipid
        print("IP-ID for stream",s,":",ipid)
        if not pkt[IP].flags == "MF": # consider fragmentation
            counter[hash_index] = (counter[hash_index] + 1) % n # increment counter
            print('incremented IP-ID')

        del pkt[IP].chksum # enforce recalculation of checksum
        packet.set_payload(bytes(pkt))
        print("here")

    packet.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(2, modify_ipid_and_accept)
try:
    print('waiting for data ...')
    nfqueue.run()
except KeyboardInterrupt:
    print('interrupt')

nfqueue.unbind()