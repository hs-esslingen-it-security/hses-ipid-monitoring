# IP-ID classification 
import statistics as st
from scapy.all import *
from scapy.layers.inet import IP
import scipy.stats as stats
import pandas as pd
import math
import json

import warnings
warnings.filterwarnings("ignore")

DEBUG_FLAG = False
TEST_FLAG = False

def debug(string):
    if DEBUG_FLAG:
        print(string)

# classify IP-ID behavior of a specific device given network trace data
# steps:
# 1. Extract tuple of src, dst, proto, and IP-ID of each paket 
# 2. Aggregate tuples
#       all 
#       per protocol 
#       per protocol and destination
# 3. Calculate the differences between consecutive IP-IDs for each grouped sequence 
# 4. Calculate heuristics for each sequence: trimmed mean E, trimmed stdev σ, min difference (-> wrap_around), max difference (-> gaps), mode (-> increment), size
# 5. Determine IP-ID class with least deviation in std / heuristics vector
# 6. Export JSON config of classified behavior

def ipid_classification(pcap_file, src_ip):
    debug(f"analyzing IP-ID behavior for {src_ip} using {pcap_file} ... ")

    ###########################################################################################################################
    # 1. Extract tuples
    ip_ids = []
    for pkt in PcapReader(pcap_file): # one file per src IP
        if IP in pkt: 
            ip_dst = str(pkt[IP].dst)
            ip_proto = str(pkt[IP].proto)
            ip_id = int(pkt[IP].id)
            
            ip_ids.append({'dst': ip_dst, 'proto': ip_proto, 'id': ip_id})
    
    config = {}
    if ip_ids:
        ip_ids_all = pd.DataFrame(ip_ids)
    
        ###########################################################################################################################
        # 2. + 3. Aggregate tuples and calculate the differences; for all IP-IDs, per protocol, per protocol and dst    
        ip_ids_all['diff_all'] = ip_ids_all['id'].diff().fillna(0)
        ip_ids_all['diff_proto'] = ip_ids_all.groupby('proto')['id'].diff().fillna(0)
        ip_ids_all['diff_proto_dst'] = ip_ids_all.groupby(['proto','dst'])['id'].diff().fillna(0)

        ###########################################################################################################################
        # 4. Calculate heuristics: trimmed mean, trimmed std, min difference, max difference, mode/most frequent value, size
        trimmed_t = 0.005 # 0.005

        stats_all = pd.DataFrame({'stdev': stats.mstats.trimmed_std(ip_ids_all['diff_all'], trimmed_t), 'mean': stats.trim_mean(ip_ids_all['diff_all'], trimmed_t), 'min': ip_ids_all['diff_all'].min(), 'max': ip_ids_all['diff_all'].max(), 'mode': ip_ids_all['diff_all'].mode(), 'size': ip_ids_all.shape[0]})
        stats_proto = ip_ids_all.groupby('proto')['diff_proto'].aggregate([('stdev', lambda s: stats.mstats.trimmed_std(s, trimmed_t)), ('mean', lambda s: stats.trim_mean(s, trimmed_t)), ('min', min), ('max', max), ('mode', st.mode), ('size', lambda s: len(s))])
        stats_proto_dst = ip_ids_all.groupby(['proto','dst'])['diff_proto_dst'].aggregate([('stdev', lambda s: stats.mstats.trimmed_std(s, trimmed_t)), ('mean', lambda s: stats.trim_mean(s, trimmed_t)), ('min', min), ('max', max), ('mode', st.mode), ('size',  lambda s: len(s))])
        debug(pd.concat([stats_all, stats_proto, stats_proto_dst], axis=0, join="inner"))

        # consider only rows/streams with > x pakets
        x = 10
        # save excluded proto_dst entries as undefined streams (if per-stream behavior)
        stats_proto_dst_undefined = stats_proto_dst[stats_proto_dst['size'] <= x]
        undefined_ = list(stats_proto_dst_undefined.index.values)

        stats_all = stats_all[stats_all['size'] > x]
        stats_proto = stats_proto[stats_proto['size'] > x]
        stats_proto_dst = stats_proto_dst[stats_proto_dst['size'] > x]
        stats_ = pd.concat([stats_all, stats_proto, stats_proto_dst], axis=0, join="inner")

        if not stats_all.empty and not stats_proto.empty and not stats_proto_dst.empty:
            ###########################################################################################################################
            # 5. Determine IP-ID class 
            global_bool = False
            per_bool = False

            # determine entry with minimal deviation -> global or per-protocol or per-stream or other?
            #   stats_all 
            #       |
            #   stats_proto 
            #       |
            #   stats_proto_dst

            stdev_all = stats_all['stdev'].values[0]
            stream_indices = []

            for index_proto, row_proto in stats_proto.iterrows():
                stdev_proto = row_proto['stdev']
                if stdev_proto < stdev_all: 
                    stream_indices.append(index_proto)

                    for index_proto_dst, row_proto_dst in stats_proto_dst.iterrows():
                        if index_proto in index_proto_dst[:len(index_proto)+1]: # matching proto
                            stdev_proto_dst = row_proto_dst['stdev']
                            if stdev_proto_dst <= stdev_proto:
                                stream_indices.append(index_proto_dst)
                                if index_proto in stream_indices: 
                                    stream_indices.remove(index_proto)

                else: # check if per-stream
                    num_streams = 0
                    streams_smaller_stdev = []
                    for index_proto_dst, row_proto_dst in stats_proto_dst.iterrows():
                        if index_proto in index_proto_dst[:len(index_proto)+1]: # matching proto
                            num_streams += 1
                            stdev_proto_dst = row_proto_dst['stdev']
                            if stdev_proto_dst < stdev_proto and stdev_proto_dst < stdev_all:
                                streams_smaller_stdev.append(index_proto_dst)
                    if len(streams_smaller_stdev) == num_streams: # all stream groups have a smaller stdev
                        stream_indices = stream_indices + streams_smaller_stdev

            #debug(stream_indices)
            if not stream_indices:
                global_bool = True
            else:
                per_bool = True

            ###########################################################################################################################
            # 6. Create and return JSON config of classified behavior
            # use window class for global and per-stream counter, constant class for constant behavior, undefined for other behavior
            config["src"] = src_ip

            # check min stdev of all groups/streams
            # bigger than max_threshold? -> too uncertain; return undefined
            max_stdev_thres = (2**16 - 1) / math.sqrt(12)
            max_window = 100000

            if global_bool:
                if stats_all['stdev'].values[0] > max_stdev_thres:
                    debug('unpredictable behavior')
                    config["type"] = "undefined"
                    return json.dumps(config)
                
                debug('global behavior')

                # JSON config
                if math.isclose(stats_all['mean'].values[0], 0.0):
                    config["type"] = "constant"
                    config["constant"] = int(ip_ids_all['id'].mode().values[0])

                else:
                    config["type"] = "global"
                    byte_swapped = bool(int(stats_all['mode'].values[0]) == 256)
                    wrap_around = int(abs(stats_all['min'].values[0]))

                    # get max difference (+/-) in sequence of differences
                    diff_sorted_min = ip_ids_all['diff_all'].sort_values()
                    trim_count = int(len(diff_sorted_min) * trimmed_t)
                    diff_sorted_min = diff_sorted_min.iloc[trim_count:-trim_count]

                    if not diff_sorted_min.empty:
                        max_ = max(abs(int(diff_sorted_min.min())), int(stats_all['max'].values[0]))
                    else:
                        max_ = int(stats_all['max'].values[0])
                    if byte_swapped:
                        max_ = min(max_window,int(max_ / 256))
                    else:
                        max_ = min(max_window,max_)

                    config["counter"] = {"increment":int(stats_all['mode'].values[0]), 
                                         "wrap_around":wrap_around, 
                                         "byte_swapped":byte_swapped,
                                         "max_gap":max_}

            elif per_bool:                
                debug('per-protocol/stream behavior')
                
                # JSON config
                config["type"] = "stream"
                config["counter"] = []

                streams_meta = stats_.loc[stream_indices]
                for stream, row in streams_meta.iterrows():
                    # protocol, e.g., 17, or protocol+dst. e.g., (17, 192.168.222.0)
                    proto_ = stream if isinstance(stream, str) else stream[0]
                    dst_ = '' if isinstance(stream, str) else stream[1]

                    if row['stdev'] < max_stdev_thres:
                        if math.isclose(row['mean'], 0.0):
                            constant_ = int(ip_ids_all[(ip_ids_all["proto"] == proto_) & (ip_ids_all["dst"] == dst_)]['id'].mode().values[0] if dst_ != '' else ip_ids_all[ip_ids_all["proto"] == proto_]['id'].mode().values[0]) # mode aggregate of stream
                            config["counter"].append({"protocol":proto_, "dst":dst_, "constant": constant_})
                        
                        else:
                            wrap_around = abs(int(stats_['min'].min()))
                            byte_swapped = bool(row['mode'] == 256)

                            # get max difference (+/-) in sequence of differences
                            if isinstance(stream, str): # per-proto
                                diff_sorted_min = ip_ids_all[ip_ids_all['proto'] == proto_]['diff_proto'].sort_values()

                            else: # per-stream
                                diff_sorted_min = ip_ids_all[(ip_ids_all['proto'] == stream[0]) & (ip_ids_all['dst'] == stream[1])]['diff_proto_dst'].sort_values()
                                
                            trim_count = int(len(diff_sorted_min) * trimmed_t)
                            diff_sorted_min = diff_sorted_min.iloc[trim_count:-trim_count]

                            if not diff_sorted_min.empty:
                                stream_max = max(abs(int(diff_sorted_min.min())), int(row['max']))
                            else:
                                stream_max = int(row['max'])
                            
                            if byte_swapped:
                                stream_max = min(max_window,int(stream_max / 256))
                            else:
                                stream_max = min(max_window,stream_max)


                            config["counter"].append({"protocol":proto_, "dst":dst_, "increment":int(row['mode']), "wrap_around":wrap_around, "max_gap":stream_max, "byte_swapped":byte_swapped})

                    else:
                        undefined_.append(stream) 
                        stream_indices.remove(stream)

                debug(f"defined streams: {stream_indices}")
                debug(f"undefined streams: {undefined_}")

                for u in undefined_:
                    proto_ = u if isinstance(u, str) else u[0]
                    dst_ = '' if isinstance(u, str) else u[1]
                    config["counter"].append({"protocol":proto_, "dst":dst_})

            else:
                debug('unpredictable behavior')
                config["type"] = "undefined"


    return json.dumps(config)





