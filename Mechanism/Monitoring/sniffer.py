from scapy.all import *
from scapy.layers.inet import IP
from window import *
from constant import *
from undefined import *
from import_config import *
from threading import Thread, Event
from time import sleep

DEBUG_FLAG = False
ALARM_FLAG = True

def debug(string):
    if DEBUG_FLAG:
        print(string)

def alarm(string):
    if ALARM_FLAG:
        print(string)

class MonitoringInstance:
    def __init__(self, src_ip, assignment_type, config):
        self.src_ip = src_ip
        self.assignment_type = assignment_type
        self.config = config

    def __str__(self):
        if self.assignment_type == 'stream':
            return f"Monitoring instance {self.src_ip}: type {self.assignment_type} -- {str(self.config.items())}"
        elif self.assignment_type == 'undefined':
            return f"Monitoring instance {self.src_ip}: type {self.assignment_type}"
        else:
            return f"Monitoring instance {self.src_ip}: type {self.assignment_type} -- {str(self.config[0])}"

# byte-swapped behavior needs special handling -> re-swap
def swap16(x):
    return int.from_bytes(x.to_bytes(2, byteorder='little'), byteorder='big', signed=False)

def ipid_monitoring(m_instances):
    def check_ipid(packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_flag = packet[IP].flags
            if ip_src in list(m_instances.keys()):
                # get instance object
                m_instance = m_instances[ip_src]
                ip_dst = packet[IP].dst
                ip_proto = packet[IP].proto
                ### global IP-ID monitoring ###
                if m_instance.assignment_type == 'global':
                    window_global = m_instance.config[0]
                    byte_swapped = m_instance.config[1]

                    if byte_swapped:
                        ipid = swap16(packet[IP].id)
                    else:
                        ipid = packet[IP].id

                    if window_global.initial == -1:
                        window_global.set_initial(ipid)
                        debug(f"initialize global IP-ID {ipid}")
                    else:
                        if window_global.compare(ipid, flags=ip_flag):
                            debug(f"{ip_src}: IP-ID {ipid} as expected")
                        else:
                            alarm(f"[!] ALARM {ip_src}: unexpected IP-ID {ipid} for global counter; window [{str(window_global.min_value_in_queue)},{str(window_global.max_value_in_queue)}]")


                ### per-protocol/per-stream IP-ID monitoring ###
                if m_instance.assignment_type == 'stream':
                    counter_dict = m_instance.config
                            
                    s = str(ip_proto) + ':' + str(ip_dst)
                    s_debug = str(ip_src) + ':' + str(ip_dst) + ':' + str(ip_proto)  
                    # identify stream counter using longest prefix match:
                    #   sort dict keys ascending by length, then iterate backwards and use String#startsWith; print the first match
                    dict_keys = sorted(list(counter_dict.keys()), key=len)
                    longest_prefix_match = ''
                    for i in range(len(dict_keys)-1, -1, -1):
                        if s.startswith(dict_keys[i]):
                            longest_prefix_match = dict_keys[i]
                            break
                    if longest_prefix_match != '' and counter_dict[longest_prefix_match][1]: # byte_swapped?
                        ipid = swap16(packet[IP].id)
                    else:
                        ipid = packet[IP].id

                    if longest_prefix_match != '': 
                        stream_counter = counter_dict[longest_prefix_match][0]
                        if stream_counter.initial == -1:
                            stream_counter.set_initial(ipid) # set initial ipid for window
                            debug(f"{ip_src}: initialize IP-ID {ipid} for stream # {s_debug} #")
                        else:
                            if  stream_counter.compare(ipid, flags=ip_flag):
                                debug(f"{ip_src}: IP-ID {ipid} as expected for stream # {s_debug} #")
                            else:
                                alarm(f"[!] ALARM {ip_src}: unexpected IP-ID {ipid} for stream # {s_debug} #; window [{str(stream_counter.min_value_in_queue)},{str(stream_counter.max_value_in_queue)}]")
                    else: 
                        alarm(f"[!] ALARM {ip_src}: IP-ID {ipid} for unspecified stream #{s_debug}#")     


                ### constant IP-ID monitoring ###
                if m_instance.assignment_type == 'constant':
                    constant_ = m_instance.config[0]
                    ipid = packet[IP].id

                    if constant_.compare(ipid, flags=ip_flag):
                        debug(f"{ip_src}: IP-ID {ipid} as expected, {str(constant_)}")
                    else:
                        alarm(f"[!] ALARM {ip_src}: unexpected IP-ID {ipid} for constant value {str(constant_)}")

                ### undefined assignment behavior ###        
                else:
                    debug(f"{ip_src}: undefined behavior")
            else:
                debug(ip_src)
                alarm(f"[!] ALARM {ip_src}: unauthorized SRC IP {ip_src}")

    return check_ipid




### main ###
# python3 sniffer.py <ips file> <config path> <iface>
if __name__ == "__main__":    
    source_ips_file = sys.argv[1]
    configs_path = sys.argv[2]
    monitoring_file = sys.argv[3]

    #iface = sys.argv[3]
    with open(source_ips_file) as f:
        ips = [line.rstrip('\n') for line in f]

    instances_ = dict()
    for ip in ips:
        config_file = configs_path + ip + '.json'
        if os.path.exists(config_file):
            # get config file
            # init monitoring instances
            src_ip, assignment_type, config = load_config(config_file)
            instance_ = MonitoringInstance(src_ip, assignment_type, config)
            instances_[ip] = instance_
            alarm(instance_)
        else:
            instance_ = MonitoringInstance(ip, 'undefined', Undefined())
            instances_[ip] = instance_
            alarm(instance_)
        
        
    # start sniffing
    alarm("[*] Start IP-ID Monitoring ...")
    sniff(offline=monitoring_file,filter="ip",prn=ipid_monitoring(instances_))
    #sniff(iface=["enp2s0","enp3s0"],filter="ip",prn=ipid_monitoring(instances_))

    # EPIC:         python3 sniffer.py /Users/sabrina/Nextcloud/ipid/network_trace_data/EPIC/traces/src_ips.txt /Users/sabrina/Nextcloud/ipid/network_trace_data/EPIC/traces/configs/ /Users/sabrina/Nextcloud/ipid/network_trace_data/EPIC/traces/monitoring.pcapng
    # MODBUS SCADA: python3 sniffer.py /Users/sabrina/Nextcloud/ipid/network_trace_data/MODBUS_SCADA/traces/src_ips.txt /Users/sabrina/Nextcloud/ipid/network_trace_data/MODBUS_SCADA/traces/configs/ /Users/sabrina/Nextcloud/ipid/network_trace_data/MODBUS_SCADA/traces/monitoring.pcap
    # QUT_DNP3:     python3 sniffer.py /Users/sabrina/Nextcloud/ipid/network_trace_data/QUT_DNP3/traces/slave/src_ips.txt /Users/sabrina/Nextcloud/ipid/network_trace_data/QUT_DNP3/traces/slave/configs/ /Users/sabrina/Nextcloud/ipid/network_trace_data/QUT_DNP3/traces/slave/replay.pcap
    # QUT_S7Comm:   python3 sniffer.py /Users/sabrina/Nextcloud/ipid/network_trace_data/QUT_S7Comm/traces/src_ips.txt /Users/sabrina/Nextcloud/ipid/network_trace_data/QUT_S7Comm/traces/configs/ /Users/sabrina/Nextcloud/ipid/network_trace_data/QUT_S7Comm/traces/monitoring.pcap
    # SWaT:         python3 sniffer.py /Users/sabrina/Nextcloud/ipid/network_trace_data/SWaT/traces/src_ips.txt /Users/sabrina/Nextcloud/ipid/network_trace_data/SWaT/traces/configs/ /Users/sabrina/Nextcloud/ipid/network_trace_data/SWaT/traces/monitoring.pcap
