## Application Test Cases

#### External Testbeds
| Testbed             | Domain             | Protocol    | Open-Source Dataset                                          | Reference                                                                                                                                                                                                                                                 |
|---------------------|--------------------|-------------|--------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| QUT\_DNP3           | Power transmission | DNP3        | [QUT\_DNP3](https://github.com/qut-infosec/2017QUT_DNP3)     | N. R. Rodofile, “Generating Attacks and Labelling Attack Datasets for Industrial Control Intrusion Detection Systems,” Ph.D. dissertation, Queensland University of Technology, 2018.                                                                     |
| QUT\_S7Comm         | Mining refinery    | S7Comm      | [QUT\_S7Comm](https://github.com/qut-infosec/2017QUT_S7comm) | N. R. Rodofile, “Generating Attacks and Labelling Attack Datasets for Industrial Control Intrusion Detection Systems,” Ph.D. dissertation, Queensland University of Technology, 2018.                                                                     |
| MODBUS TCP SCADA #1 | Liquid pump        | Modbus      | [ICS_PCAPS](https://github.com/tjcruz-dei/ICS_PCAPS)         | I. Frazao, P. H. Abreu, T. Cruz, H. Araujo, and P. Simoes, “Denial of Service Attacks: Detecting the Frailties of Machine Learning Algorithms in the Classification Process,” in Critical Information Infrastructures Security Conference (CRITIS), 2019. |
| EPIC                | Smart grid         | IEC 61850   | --                                                           | S. Adepu, N. K. Kandasamy, and A. Mathur, “EPIC: An Electric Power Testbed for Research and Training in Cyber Physical Systems Security,” in Computer Security: ESORICS International Workshops, CyberICPS and SECPRE, 2018.                              |
| SWaT                | Water treatment    | EtherNet/IP | --                                                           | iTrust, Centre for Research in Cyber Security, Singapore University of Technology and Design, SWaT Testbed Technical Details. 2020.                                                                                                                       |

### Classification
| Dataset         | Data used for Classification                   | Device                  | Classified Behavior | Remark                       |
|-----------------|------------------------------------------------|-------------------------|---------------------|------------------------------|
| QUT_DNP3        | control/training/frequent/master.pcap          | 192.168.10.221 / Master | global              |                              |
|                 | control/training/frequent/slave.pcap           | 192.168.10.222 / Slave  | global              |                              |
|                 | control/training/frequent/slave.pcap           | 192.168.10.1 / HMI      | global              | classified wrong increment   |
| QUT_S7Comm      | s7_process_attacks/master.pcap                 | 10.10.10.10 / Master    | global              |                              |
|                 | s7_process_attacks/master.pcap                 | 10.10.10.20 / HMI       | global              |                              |
| MODBUS SCADA #1 | eth2dump-clean-6h_1                            | 172.27.224.250 / PLC    | global              |                              |
|                 | "                                              | 172.27.224.251 / RTU    | global              |                              |
|                 | "                                              | 172.27.224.70 / HMI     | global              |                              |
| EPIC            | Index28-35; duplicate removal: editcap -d -w 5 | 172.16.1.41 / GPLC      | per-stream          |                              |
|                 | "                                              | 172.16.2.41 / TPLC      | per-stream          |                              |
|                 | "                                              | 172.16.3.41 / MPLC      | per-stream          |                              |
|                 | "                                              | 172.16.4.41 / SPLC      | per-stream          |                              |
|                 | "                                              | 172.16.5.41 / CPLC      | per-stream          |                              |
|                 | "                                              | 172.16.1.11 / GIED1     | global              | classified wrong increment   |
|                 | "                                              | 172.16.1.12 / GIED2     | global              | classified wrong increment   |
|                 | "                                              | 172.16.2.11 / TIED1     | global              |                              |
|                 | "                                              | 172.16.2.12 / TIED2     | global              |                              |
|                 | "                                              | 172.16.2.13 / TIED3     | global              | classified wrong wrap-around |
|                 | "                                              | 172.16.3.11 / MIED1     | global              |                              |
|                 | "                                              | 172.16.3.12 / MIED2     | global              |                              |
|                 | "                                              | 172.16.4.11 / SIED1     | global              |                              |
|                 | "                                              | 172.16.4.12 / SIED2     | global              |                              |
|                 | "                                              | 172.16.4.13 / SIED3     | global              |                              |
|                 | "                                              | 172.16.4.14 / SIED4     | global              |                              |
| SWaT            | SWaT_Day_5_00001_20210629091544.pcap           | 192.168.1.10 / P1 PCN   | per-stream          |                              |
|                 | "                                              | 192.168.1.20 / P2 PCN   | per-stream          |                              |
|                 | "                                              | 192.168.1.30 / P3 PCN   | per-stream          |                              |
|                 | "                                              | 192.168.1.40 / P4 PCN   | per-stream          |                              |
|                 | "                                              | 192.168.1.50 / P5 PCN   | per-stream          |                              |
|                 | "                                              | 192.168.1.60 / P6 PCN   | per-stream          |                              |


### Monitoring
| Dataset         | Data used for Monitoring             | Remark |
|-----------------|--------------------------------------|--------|
| QUT_DNP3        | control/testing/frequent/master.pcap |        |
| QUT_S7Comm      | control set master.pcap              |        |
| MODBUS SCADA #1 | eth2dump-clean-1h_1                  |        |
| EPIC            | Index20-27                           |        |
| SWaT            | SWaT_Day_5_00007_20210629104502.pcap |        |
