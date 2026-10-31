# Evidence trace: 172.16.0.1

100 records · BLOCK 96 · ALLOW 4 · classes DOS 40, DDOS 24, PORT_SCAN 24, BRUTE_FORCE 12

## Policy timeline

- **P001 ACTIVATE** after F000014 (seq 14), covers seq 15–64 (through F000064). Trigger: BRUTE_FORCE a1_conf 1.000 >= 0.95. Evidence: CLASSIFIER_ONLY, a2 0.4544, A4 G001 count 1.
- **P001 EXPIRE** after F000064 (seq 64); IP needs a new trigger.
- **P002 ACTIVATE** after F000068 (seq 68), covers seq 69–118 (through F000118). Trigger: DOS a1_conf 1.000 >= 0.95. Evidence: CLASSIFIER_ONLY, a2 0.5597, A4 G002 count 1.
- **P002 EXPIRE** after F000118 (seq 118); IP needs a new trigger.
- **P003 ACTIVATE** after F000120 (seq 120), covers seq 121–170 (through F000170). Trigger: DDOS a1_conf 1.000 >= 0.95. Evidence: CLASSIFIER_ONLY, a2 0.4934, A4 G003 count 1.
- **P003 EXPIRE** after F000170 (seq 170); IP needs a new trigger.
- **P004 ACTIVATE** after F000171 (seq 171), covers seq 172–200 (through F000200). Trigger: PORT_SCAN a1_conf 1.000 >= 0.95. Evidence: CLASSIFIER_ONLY, a2 0.4069, A4 G004 count 1.
- **P004 EXPIRE** after F000200 (seq 200); IP needs a new trigger.

## Trigger P001: F000014 (seq 14)

1. **A1 Threat:** BRUTE_FORCE conf 1.000 (top-2 BENIGN 0.000)
2. **A2 Anomaly:** score 0.454, anomalous=False, top Fwd IAT Min z=12.9, PSH Flag Count z=7.8, act_data_pkt_fwd z=7.5
3. **A3 Fusion:** CLASSIFIER_ONLY: A1 says BRUTE_FORCE (1.00), A2 normal (score 0.454, top Fwd IAT Min) -> BRUTE_FORCE, BLOCK
4. **A4 Correlation:** group G001, members F000014
5. **A5 Defense:** BRUTE_FORCE a1_conf 1.000 >= 0.95 → P001 SOURCE_IP 172.16.0.1
6. **Replay:** ALLOW (the triggering flow is allowed; the policy applies from the next seq)

## Trigger P002: F000068 (seq 68)

1. **A1 Threat:** DOS conf 1.000 (top-2 BENIGN 0.000)
2. **A2 Anomaly:** score 0.560, anomalous=False, top Idle Std z=6581299.0, Active Std z=4535487.0, Bwd IAT Min z=669657.6
3. **A3 Fusion:** CLASSIFIER_ONLY: A1 says DOS (1.00), A2 normal (score 0.560, top Idle Std) -> DOS, BLOCK
4. **A4 Correlation:** group G002, members F000068
5. **A5 Defense:** DOS a1_conf 1.000 >= 0.95 → P002 SOURCE_IP 172.16.0.1
6. **Replay:** ALLOW (the triggering flow is allowed; the policy applies from the next seq)

## Trigger P003: F000120 (seq 120)

1. **A1 Threat:** DDOS conf 1.000 (top-2 BENIGN 0.000)
2. **A2 Anomaly:** score 0.493, anomalous=False, top Bwd Avg Bulk Rate z=23956612.0, Bwd Avg Bytes/Bulk z=11595.0, Packet Length Variance z=27.0
3. **A3 Fusion:** CLASSIFIER_ONLY: A1 says DDOS (1.00), A2 normal (score 0.493, top Bwd Avg Bulk Rate) -> DDOS, BLOCK
4. **A4 Correlation:** group G003, members F000120
5. **A5 Defense:** DDOS a1_conf 1.000 >= 0.95 → P003 SOURCE_IP 172.16.0.1
6. **Replay:** ALLOW (the triggering flow is allowed; the policy applies from the next seq)

## Trigger P004: F000171 (seq 171)

1. **A1 Threat:** PORT_SCAN conf 1.000 (top-2 BENIGN 0.000)
2. **A2 Anomaly:** score 0.407, anomalous=False, top Bwd Packets/s z=227.6, Flow Packets/s z=224.1, Fwd Packets/s z=220.3
3. **A3 Fusion:** CLASSIFIER_ONLY: A1 says PORT_SCAN (1.00), A2 normal (score 0.407, top Bwd Packets/s) -> PORT_SCAN, BLOCK
4. **A4 Correlation:** group G004, members F000171
5. **A5 Defense:** PORT_SCAN a1_conf 1.000 >= 0.95 → P004 SOURCE_IP 172.16.0.1
6. **Replay:** ALLOW (the triggering flow is allowed; the policy applies from the next seq)

## Every record

| seq | record_id | dst | A1 | A2 | A2 top | A3 | A4 | A5 | action |
|---|---|---|---|---|---|---|---|---|---|
| 14 | F000014 | 192.168.10.50:22 | BRUTE_FORCE 1.000 | 0.454 | Fwd IAT Min z=12.9, PSH Flag Count z=7.8 | BRUTE_FORCE · CLASSIFIER_ONLY · BLOCK | G001 n=1 | P001 | ALLOW |
| 18 | F000018 | 192.168.10.50:21 | BRUTE_FORCE 1.000 | 0.421 | Down/Up Ratio z=8.7, Init_Win_bytes_forward z=3.6 | BRUTE_FORCE · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 20 | F000020 | 192.168.10.50:22 | BRUTE_FORCE 1.000 | 0.454 | Fwd IAT Min z=11.5, Down/Up Ratio z=8.0 | BRUTE_FORCE · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 25 | F000025 | 192.168.10.50:21 | BRUTE_FORCE 1.000 | 0.421 | Down/Up Ratio z=8.7, Init_Win_bytes_forward z=3.6 | BRUTE_FORCE · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 27 | F000027 | 192.168.10.50:21 | BRUTE_FORCE 1.000 | 0.421 | Down/Up Ratio z=8.7, Init_Win_bytes_forward z=3.6 | BRUTE_FORCE · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 28 | F000028 | 192.168.10.50:21 | BRUTE_FORCE 1.000 | 0.421 | Down/Up Ratio z=8.7, Init_Win_bytes_forward z=3.6 | BRUTE_FORCE · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 29 | F000029 | 192.168.10.50:21 | BRUTE_FORCE 1.000 | 0.421 | Down/Up Ratio z=8.7, Fwd IAT Min z=4.6 | BRUTE_FORCE · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 32 | F000032 | 192.168.10.50:21 | BRUTE_FORCE 1.000 | 0.421 | Down/Up Ratio z=8.7, Fwd IAT Min z=4.5 | BRUTE_FORCE · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 34 | F000034 | 192.168.10.50:22 | BRUTE_FORCE 1.000 | 0.454 | Fwd IAT Min z=9.7, Down/Up Ratio z=8.0 | BRUTE_FORCE · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 37 | F000037 | 192.168.10.50:21 | BRUTE_FORCE 1.000 | 0.421 | Down/Up Ratio z=8.7, Init_Win_bytes_forward z=3.6 | BRUTE_FORCE · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 45 | F000045 | 192.168.10.50:21 | BRUTE_FORCE 1.000 | 0.421 | Down/Up Ratio z=8.7, Init_Win_bytes_forward z=3.6 | BRUTE_FORCE · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 48 | F000048 | 192.168.10.50:21 | BRUTE_FORCE 1.000 | 0.422 | Down/Up Ratio z=8.7, Fwd IAT Min z=4.1 | BRUTE_FORCE · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 50 | F000050 | 192.168.10.50:80 | DOS 1.000 | 0.516 | Packet Length Variance z=77.5, Bwd Packet Length Mean z=15.6 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 56 | F000056 | 192.168.10.50:80 | DOS 1.000 | 0.632 ⚑ | Bwd Avg Bulk Rate z=45976284.0, Idle Std z=21575018.0 | DOS · CORROBORATED · BLOCK | skipped | skipped | BLOCK (P001) |
| 58 | F000058 | 192.168.10.50:80 | DOS 1.000 | 0.536 | Active Min z=14255.0, Active Mean z=7209.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P001) |
| 68 | F000068 | 192.168.10.50:80 | DOS 1.000 | 0.560 | Idle Std z=6581299.0, Active Std z=4535487.0 | DOS · CLASSIFIER_ONLY · BLOCK | G002 n=1 | P002 | ALLOW |
| 74 | F000074 | 192.168.10.50:80 | DOS 1.000 | 0.514 | Bwd Avg Bulk Rate z=39982760.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 75 | F000075 | 192.168.10.50:80 | DOS 1.000 | 0.513 | Bwd Avg Bulk Rate z=25997756.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 76 | F000076 | 192.168.10.50:80 | DOS 1.000 | 0.522 | Packet Length Variance z=141.2, Bwd Packet Length Std z=17.5 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 77 | F000077 | 192.168.10.50:80 | DOS 1.000 | 0.505 | Bwd Avg Bulk Rate z=25939596.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 79 | F000079 | 192.168.10.50:80 | DOS 1.000 | 0.511 | Packet Length Variance z=52.7, Total Length of Bwd Packets z=13.3 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 82 | F000082 | 192.168.10.50:80 | DOS 1.000 | 0.485 | Bwd Avg Bulk Rate z=42317520.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 83 | F000083 | 192.168.10.50:80 | DOS 1.000 | 0.499 | Packet Length Variance z=71.7, Total Length of Bwd Packets z=13.3 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 84 | F000084 | 192.168.10.50:80 | DOS 1.000 | 0.510 | Bwd Avg Bulk Rate z=19422110.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 85 | F000085 | 192.168.10.50:80 | DOS 1.000 | 0.505 | Packet Length Variance z=77.4, Total Length of Bwd Packets z=13.3 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 88 | F000088 | 192.168.10.50:80 | DOS 1.000 | 0.515 | Bwd Avg Bulk Rate z=46566264.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 89 | F000089 | 192.168.10.50:80 | DOS 1.000 | 0.519 | Bwd Avg Bulk Rate z=25997756.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 90 | F000090 | 192.168.10.50:80 | DOS 1.000 | 0.520 | Bwd Avg Bulk Rate z=39845360.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 91 | F000091 | 192.168.10.50:80 | DOS 1.000 | 0.502 | Bwd Avg Bulk Rate z=23663264.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 92 | F000092 | 192.168.10.50:80 | DOS 1.000 | 0.510 | Packet Length Variance z=42.7, Flow Bytes/s z=31.9 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 93 | F000093 | 192.168.10.50:80 | DOS 1.000 | 0.508 | Bwd Avg Bulk Rate z=45292968.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 94 | F000094 | 192.168.10.50:80 | DOS 1.000 | 0.524 | Bwd Avg Bulk Rate z=39982760.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 95 | F000095 | 192.168.10.50:80 | DOS 1.000 | 0.502 | Packet Length Variance z=77.4, Total Length of Bwd Packets z=13.3 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 97 | F000097 | 192.168.10.50:80 | DOS 1.000 | 0.509 | Bwd Avg Bulk Rate z=45116732.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 98 | F000098 | 192.168.10.50:80 | DOS 1.000 | 0.537 | Bwd Avg Bulk Rate z=45830040.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 99 | F000099 | 192.168.10.50:80 | DOS 1.000 | 0.519 | Bwd Avg Bulk Rate z=24106028.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 100 | F000100 | 192.168.10.50:80 | DOS 1.000 | 0.538 | Bwd Avg Bulk Rate z=35787036.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 101 | F000101 | 192.168.10.50:80 | DOS 1.000 | 0.514 | Bwd Avg Bulk Rate z=45116732.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 103 | F000103 | 192.168.10.50:80 | DOS 1.000 | 0.525 | Bwd Avg Bulk Rate z=26840276.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 104 | F000104 | 192.168.10.50:80 | DOS 1.000 | 0.533 | Bwd Avg Bulk Rate z=39708904.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 105 | F000105 | 192.168.10.50:80 | DOS 1.000 | 0.512 | Bwd Avg Bulk Rate z=44768340.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 106 | F000106 | 192.168.10.50:80 | DOS 1.000 | 0.508 | Bwd Avg Bulk Rate z=39982760.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 107 | F000107 | 192.168.10.50:80 | DOS 1.000 | 0.533 | Bwd Avg Bulk Rate z=45649608.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 109 | F000109 | 192.168.10.50:80 | DOS 1.000 | 0.542 | Fwd Avg Bulk Rate z=1921.0, Fwd Avg Bytes/Bulk z=1660.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 110 | F000110 | 192.168.10.50:80 | DOS 1.000 | 0.521 | Packet Length Variance z=72.1, Flow Bytes/s z=49.8 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 111 | F000111 | 192.168.10.50:80 | DOS 1.000 | 0.519 | Bwd Avg Bulk Rate z=25939596.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 112 | F000112 | 192.168.10.50:80 | DOS 1.000 | 0.533 | Bwd Avg Bulk Rate z=40121108.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 113 | F000113 | 192.168.10.50:80 | DOS 1.000 | 0.529 | Flow Bytes/s z=137.9, Packet Length Variance z=45.2 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 114 | F000114 | 192.168.10.50:80 | DOS 1.000 | 0.518 | Packet Length Variance z=112.0, Bwd Packet Length Std z=17.5 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 115 | F000115 | 192.168.10.50:80 | DOS 1.000 | 0.517 | Packet Length Variance z=93.4, Bwd Packet Length Mean z=15.6 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 116 | F000116 | 192.168.10.50:80 | DOS 1.000 | 0.513 | Packet Length Variance z=66.7, Bwd Packet Length Mean z=15.6 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 118 | F000118 | 192.168.10.50:80 | DOS 1.000 | 0.515 | Bwd Avg Bulk Rate z=17228826.0, Bwd Avg Bytes/Bulk z=11595.0 | DOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P002) |
| 120 | F000120 | 192.168.10.50:80 | DDOS 1.000 | 0.493 | Bwd Avg Bulk Rate z=23956612.0, Bwd Avg Bytes/Bulk z=11595.0 | DDOS · CLASSIFIER_ONLY · BLOCK | G003 n=1 | P003 | ALLOW |
| 121 | F000121 | 192.168.10.50:80 | DDOS 1.000 | 0.491 | Packet Length Variance z=90.6, Bwd Packet Length Mean z=19.7 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 122 | F000122 | 192.168.10.50:80 | DDOS 1.000 | 0.498 | Bwd Avg Bulk Rate z=833761.0, Bwd Avg Bytes/Bulk z=12970.0 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 123 | F000123 | 192.168.10.50:80 | DDOS 1.000 | 0.500 | Active Min z=1532.5, Active Mean z=775.0 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 125 | F000125 | 192.168.10.50:80 | DDOS 1.000 | 0.492 | Packet Length Variance z=114.2, Bwd Packet Length Std z=16.2 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 126 | F000126 | 192.168.10.50:80 | DDOS 1.000 | 0.525 | Active Min z=7544.7, Active Mean z=3815.5 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 127 | F000127 | 192.168.10.50:3030 | PORT_SCAN 1.000 | 0.415 | Bwd Packets/s z=280.6, Flow Packets/s z=276.3 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 128 | F000128 | 192.168.10.50:80 | DDOS 1.000 | 0.522 | Active Min z=5967.2, Active Mean z=3017.7 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 130 | F000130 | 192.168.10.50:3945 | PORT_SCAN 1.000 | 0.414 | Bwd Packets/s z=227.6, Flow Packets/s z=224.1 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 131 | F000131 | 192.168.10.50:80 | DDOS 1.000 | 0.487 | Packet Length Variance z=137.6, Bwd Packet Length Std z=20.6 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 132 | F000132 | 192.168.10.50:80 | DDOS 1.000 | 0.512 | Active Min z=5848.6, Active Mean z=2957.7 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 133 | F000133 | 192.168.10.50:80 | DDOS 1.000 | 0.504 | Active Min z=1180.6, Active Mean z=597.1 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 139 | F000139 | 192.168.10.50:80 | DDOS 1.000 | 0.521 | Active Min z=7310.4, Active Mean z=3697.0 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 140 | F000140 | 192.168.10.50:80 | DDOS 1.000 | 0.491 | Packet Length Variance z=46.1, Bwd Packet Length Mean z=15.6 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 141 | F000141 | 192.168.10.50:80 | DDOS 1.000 | 0.521 | Active Min z=2262.1, Active Mean z=1144.0 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 142 | F000142 | 192.168.10.50:80 | DDOS 1.000 | 0.522 | Active Min z=2530.9, Active Mean z=1279.9 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 143 | F000143 | 192.168.10.50:80 | DDOS 1.000 | 0.483 | Packet Length Variance z=40.7, Total Length of Bwd Packets z=13.3 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 144 | F000144 | 192.168.10.50:80 | DDOS 1.000 | 0.508 | Active Min z=1683.6, Active Mean z=851.4 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 145 | F000145 | 192.168.10.50:80 | DDOS 1.000 | 0.489 | Packet Length Variance z=172.0, Bwd Packet Length Std z=23.0 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 146 | F000146 | 192.168.10.50:80 | DDOS 1.000 | 0.522 | Active Min z=5265.2, Active Mean z=2662.7 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 147 | F000147 | 192.168.10.50:80 | DDOS 1.000 | 0.482 | Packet Length Variance z=50.1, Total Length of Bwd Packets z=13.3 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 148 | F000148 | 192.168.10.50:80 | DDOS 1.000 | 0.501 | Bwd Avg Bulk Rate z=45292968.0, Bwd Avg Bytes/Bulk z=11595.0 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 150 | F000150 | 192.168.10.50:80 | DDOS 1.000 | 0.494 | Packet Length Variance z=111.3, Bwd Packet Length Mean z=19.7 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 155 | F000155 | 192.168.10.50:5357 | PORT_SCAN 1.000 | 0.403 | Bwd Packets/s z=177.4, Flow Packets/s z=174.6 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P003) |
| 171 | F000171 | 192.168.10.50:1721 | PORT_SCAN 1.000 | 0.407 | Bwd Packets/s z=227.6, Flow Packets/s z=224.1 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | G004 n=1 | P004 | ALLOW |
| 172 | F000172 | 192.168.10.50:5631 | PORT_SCAN 1.000 | 0.421 | Bwd Packets/s z=670.9, Flow Packets/s z=660.5 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 173 | F000173 | 192.168.10.50:10010 | PORT_SCAN 1.000 | 0.436 | Bwd Packets/s z=6040.4, Flow Packets/s z=5946.8 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 174 | F000174 | 192.168.10.50:1839 | PORT_SCAN 1.000 | 0.414 | Bwd Packets/s z=482.9, Flow Packets/s z=475.4 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 175 | F000175 | 192.168.10.50:5801 | PORT_SCAN 1.000 | 0.421 | Bwd Packets/s z=287.3, Flow Packets/s z=282.9 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 176 | F000176 | 192.168.10.50:10626 | PORT_SCAN 1.000 | 0.425 | Bwd Packets/s z=241.3, Flow Packets/s z=237.6 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 177 | F000177 | 192.168.10.50:19350 | PORT_SCAN 1.000 | 0.427 | Bwd Packets/s z=274.3, Flow Packets/s z=270.0 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 178 | F000178 | 192.168.10.50:32769 | PORT_SCAN 1.000 | 0.415 | Bwd Packets/s z=191.5, Flow Packets/s z=188.5 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 179 | F000179 | 192.168.10.50:5190 | PORT_SCAN 1.000 | 0.421 | Bwd Packets/s z=929.0, Flow Packets/s z=914.6 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 180 | F000180 | 192.168.10.50:3333 | PORT_SCAN 1.000 | 0.415 | Bwd Packets/s z=274.3, Flow Packets/s z=270.0 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 181 | F000181 | 192.168.10.50:1049 | PORT_SCAN 1.000 | 0.414 | Bwd Packets/s z=287.3, Flow Packets/s z=282.9 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 182 | F000182 | 192.168.10.50:8080 | PORT_SCAN 1.000 | 0.391 | Bwd Packets/s z=87.2, Flow Packets/s z=85.9 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 185 | F000185 | 192.168.10.50:61532 | PORT_SCAN 1.000 | 0.446 | Bwd Packets/s z=355.0, Flow Packets/s z=349.5 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 186 | F000186 | 192.168.10.50:5560 | PORT_SCAN 1.000 | 0.425 | Bwd Packets/s z=204.5, Flow Packets/s z=201.3 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 187 | F000187 | 192.168.10.50:4000 | PORT_SCAN 1.000 | 0.437 | Bwd Packets/s z=274.3, Flow Packets/s z=270.0 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 188 | F000188 | 192.168.10.50:139 | PORT_SCAN 1.000 | 0.404 | Init_Win_bytes_backward z=245.4, Fwd Packets/s z=36.4 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 190 | F000190 | 192.168.10.50:1102 | PORT_SCAN 1.000 | 0.427 | Bwd Packets/s z=241.3, Flow Packets/s z=237.6 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 191 | F000191 | 192.168.10.50:8100 | PORT_SCAN 1.000 | 0.440 | Bwd Packets/s z=274.3, Flow Packets/s z=270.0 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 192 | F000192 | 192.168.10.50:7777 | PORT_SCAN 1.000 | 0.442 | Bwd Packets/s z=525.0, Flow Packets/s z=516.8 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 193 | F000193 | 192.168.10.50:1461 | PORT_SCAN 1.000 | 0.431 | Bwd Packets/s z=482.9, Flow Packets/s z=475.4 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 194 | F000194 | 192.168.10.50:5678 | PORT_SCAN 1.000 | 0.439 | Bwd Packets/s z=287.3, Flow Packets/s z=282.9 | PORT_SCAN · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 195 | F000195 | 192.168.10.50:80 | DDOS 1.000 | 0.490 | Bwd Avg Bulk Rate z=20270980.0, Bwd Avg Bytes/Bulk z=11595.0 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 198 | F000198 | 192.168.10.50:80 | DDOS 1.000 | 0.518 | Active Min z=4982.9, Active Mean z=2519.9 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
| 199 | F000199 | 192.168.10.50:80 | DDOS 1.000 | 0.516 | Active Min z=5272.3, Active Mean z=2666.3 | DDOS · CLASSIFIER_ONLY · BLOCK | skipped | skipped | BLOCK (P004) |
