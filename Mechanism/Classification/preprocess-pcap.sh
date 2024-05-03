#!/bin/bash
# read pcap and split pcap into multiple files, one for each src ip address
PCAP=$1 # raw pcap file
DIR_CAP="${PCAP%/*}/captures"
DIR_CON="${PCAP%/*}/configs" # baselining configs for each source

mkdir -p "$DIR_CAP"
mkdir -p "$DIR_CON"
tshark -r "$PCAP" -T fields -e ip.src | sort | uniq | sed -r '/^\s*$/d'> "${PCAP%%.*}_src_ips.txt" # identify unique src ips

# pre-process packet capture: split by source IP
while read -r SRC; do
    tcpdump -n -r "$PCAP" -w "$DIR_CAP/$SRC.pcap" "ip src $SRC"
done < "${PCAP%%.*}_src_ips.txt"

# classify
# for each source IP: run baselining and store config
SRCIPS=${2:-"${PCAP%%.*}_src_ips.txt"} 
while read -r SRC; do
    # parameters: pcap + ip
    #             "$DIR_CAP/$SRC.pcap", "$SRC"
    python3 -c "import baselining as b; config=b.ipid_classification('$DIR_CAP/$SRC.pcap','$SRC'); print(config)" > "$DIR_CON/$SRC.json"
    cat "$DIR_CON/$SRC.json" 
done < "$SRCIPS"

# start monitoring 
# python3 sniffer.py <ips file> <config path> <iface>