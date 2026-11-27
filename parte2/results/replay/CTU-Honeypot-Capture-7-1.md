# Replay de CTU-Honeypot-Capture-7-1

- pcap: `s1_somfy_60min.pcap`, 5012 pacotes, 3599 s à velocidade original
- IP 192.168.1.158 reescrito para 10.10.1.10

| | IoT-23 original | Gateway (replay) |
|---|---|---|
| fluxos | 0 | 5 |
| proto | {} | {'icmp': 2, 'udp': 2, 'tcp': 1} |
| conn_state (top 6) | {} | {'OTH': 3, 'SF': 2} |
| porta destino (top 5) | {} | {0: 2, 53: 1, 123: 1, 443: 1} |
| mediana duration | None | 1796.99 |
| mediana orig_bytes | None | 70748.5 |
| mediana resp_bytes | None | 254.0 |
| mediana orig_pkts | None | 4.0 |
| mediana resp_pkts | None | 2.0 |

## Nota: referência alternativa (Zeek sobre o pcap original)

O `conn.log` rotulado do IoT-23 desta captura só tem 7 fluxos do 192.168.1.158, todos anteriores ao
troço de 60 min usado (`pcap_t0` = 1562164876.66), por isso a coluna "IoT-23 original" fica vazia.
Como referência, correu-se o Zeek 9.0.1 (o mesmo do gateway) sobre `s1_somfy_60min.pcap` antes da
reescrita (`zeek -C -r`):

| Fluxo | Zeek sobre o pcap original | Gateway (replay) |
|---|---|---|
| udp → 192.168.1.1:53 (DNS) | SF, 0,064 s | SF, 0,065 s |
| udp → 5.199.135.170:123 (NTP) | SF, 0,028 s | SF, 0,028 s |
| tcp → 18.195.134.106:443 | OTH, 3594,29 s | OTH, 3594,56 s |

Os 3 fluxos coincidem (portas, estados e durações). Os 2 fluxos ICMP a mais no gateway são artefactos
do banco de ensaio: o `ping` ao gateway feito pelo `replay.sh` para obter o MAC, e um ICMP
"destination unreachable" (tipo 3) do servidor 10.20.0.10, porque os IPs públicos não existem no lab.
