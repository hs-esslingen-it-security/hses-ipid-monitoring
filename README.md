# Monitoring IP-ID Behavior for Spoofed IPv4 Traffic Detection
This README provides details on the mechanism proposed in the according paper.

## Mechanism: Classification and Monitoring Algorithm
To run the classification on selected capture data, run the [preprocess-pcap.sh](mechanism/classification/preprocess-pcap.sh) file.
For monitoring, [sniffer.py](mechanism/monitoring/sniffer.py) is the main file.

## Proof-of-Concept (PoC)
In *PoC*, we provide the traffic captured for the PoC as well as the resulting classification files. We further provide the code to implement the mimicking of a global and a per-stream IP-ID counter implementation.

## Evaluation
We provide an overview of the application test cases and example classification results obtained using the external testbed data as described in the paper.
