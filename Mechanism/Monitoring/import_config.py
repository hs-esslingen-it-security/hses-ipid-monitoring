# load IP-ID config from JSON file and initialize counter
import json
from window import *
from constant import *
from undefined import *

TEST_FLAG = False

# Example config-outlines
#
# CONSTANT
# {
#	"src":<srcIP>,
#	"type":"constant",
#	"constant": <c>
# }
#
# GLOBAL:
# {
#	"src":<srcIP>,
#	"type":"global",
#	"counter": {"increment":<i>, "wrap_around":<wa>, "byte_swapped":<true/false>, "max_gap":<i>}
# }
#
# PER-STREAM:
# {
#	"src":<srcIP>,
#	"type":"stream",
#	"counter": [ 
#				{"protocol":<protocol>, "dst":<dstIP>, "increment":<i>, "wrap_around":<wa>, "byte_swapped":<true/false>, "max_gap":<i>},    # default
#               {"protocol":<protocol>, "dst":<dstIP>, "constant": <c>},                                                                # constant stream behavior
#               {"protocol":<protocol>, "dst":<dstIP>}, ...                                                                             # undefined stream behavior
#			   ]
# }

# returns monitoring object (per group); object is one of Constant, Window, Undefined
#  structure [object, bool byte-swapped] or dict with stream-keys
def load_config(config_file_name):

    # scaling/sizing factors
    window_size_sf = 2 
    window_sliding_f = 0.25
    min_window_size = 2

    with open(config_file_name) as f:
        # return JSON object as dictionary
        f.seek(0)
        ip_id_config = json.load(f)
        type_ = ip_id_config['type']

        if type_ == 'constant':
            # ... constant config
            counter = [Constant(constant=ip_id_config['constant']), False]

        if type_ == 'global':
            # ... global config
            byte_swapped_ = ip_id_config['counter']['byte_swapped']
            window_size = max(min_window_size, int(ip_id_config['counter']['max_gap'] * window_size_sf)+1)
            increment_ = ip_id_config['counter']['increment'] if not byte_swapped_ else 1
            
            counter = [Window(increment=increment_,
                            wrap_around=ip_id_config['counter']['wrap_around'],
                            length=window_size, shift_factor=window_sliding_f),
                            byte_swapped_]

        if type_ == 'stream':
            # ... per-stream config
            counter = {}
            for stream in ip_id_config['counter']:
                key_ = str(stream['protocol']) + ':' + str(stream['dst'])

                if "constant" in stream:
                    counter[key_] = [Constant(constant=stream['constant']), False]
                elif "increment" in stream:
                    byte_swapped_ = stream['byte_swapped']
                    window_size = max(min_window_size, int(stream['max_gap'] * window_size_sf)+1)
                    increment_ = stream['increment'] if not byte_swapped_ else 1

                    counter[key_] = [Window(increment=increment_,
                                            wrap_around=stream['wrap_around'],
                                            length=window_size, shift_factor=window_sliding_f),
                                            stream['byte_swapped']]
                else:
                    counter[key_] = [Undefined(), False]

        if 'counter' in locals():
            return ip_id_config['src'], type_, counter
        else:
            return ip_id_config['src'], type_, None


if TEST_FLAG:
    src, assignment_type, config = load_config('test')

    print(assignment_type)
    for k, v in config.items():
        print(k, v[0])
