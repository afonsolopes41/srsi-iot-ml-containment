# Contratos entre módulos (Parte 2)

Este documento fixa o que cada parte entrega à seguinte, para podermos trabalhar em paralelo.
**Qualquer alteração a um contrato tem de ser combinada com quem o consome e anotada no
histórico no fim do documento.** Os contratos em código estão em `src/srsi/` e são verificados
pelos testes em `tests/`.

```
 IoT-23 conn.log.labeled ─┐                                   ┌─> results/offline/  (§6)
                          ├─(§1) DataFrame canónico ─(§2) X ──┤
 gateway: Zeek conn.log ──┘        srsi.zeeklog      features  └─(§3) models/<nome>/
          conn_interim.log                                              │
                                                                        ▼
                         (§4) logs/gateway/flows.jsonl  <── detetor online
                         (§4) logs/gateway/decisions.jsonl <── decisão (k de w)
                         (§5) nft set inet srsi quarantine <── contenção
                         (§6) logs/attacker|nodes/*.jsonl  ──> T_c, quarentenas indevidas
```

## Endereçamento (docker-compose.yml)

| Nó | Rede | IP | Papel |
|---|---|---|---|
| device1 | iot1 10.10.1.0/24 | 10.10.1.10 | dispositivo IoT (tráfego benigno) |
| device2 | iot2 10.10.2.0/24 | 10.10.2.10 | dispositivo IoT (tráfego benigno) |
| attacker | iot3 10.10.3.0/24 | 10.10.3.10 | dispositivo infetado (replay IoT-23) |
| server | ext 10.20.0.0/24 | 10.20.0.10 | "Internet" (HTTP + destino por omissão) |
| gateway | todas | x.x.x.254 | Zeek, deteção, decisão, nftables |

O gateway tem MAC fixo em cada rede (`02:00:0a:0a:0N:fe`, `02:00:0a:14:00:fe` na ext): o
`tcprewrite` usa-o como MAC de destino (`--enet-dmac`) para os pacotes chegarem ao gateway.

## §1 Registo de fluxo canónico (`srsi.zeeklog`)

Todas as origens são convertidas para o mesmo `pandas.DataFrame`, colunas por esta ordem
(`CANONICAL_COLUMNS`):

| Coluna | Tipo | Origem Zeek | Nota |
|---|---|---|---|
| `ts`, `uid`, `orig_h`, `orig_p`, `resp_h` | float, str, str, Int32, str | `ts`, `uid`, `id.*` | identificação; **nunca** são features |
| `resp_p` | Int32 | `id.resp_p` | só entra agrupada (§2) |
| `proto`, `service`, `conn_state`, `history` | str (`"-"` se vazio) | iguais | |
| `duration`, `orig_bytes`, `resp_bytes`, `missed_bytes`, `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes` | float (NaN se vazio) | iguais | |
| `label` | Int8: 0 benigno, 1 malicioso, NA no gateway | IoT-23 `label` | |
| `detailed_label` | str | IoT-23 `detailed-label` | família/tipo (ex. `PartOfAHorizontalPortScan`) |
| `capture` | str | nome da captura | **chave da divisão treino/teste** |
| `partial` | bool | `True` se veio de `conn_interim.log` | |

Funções: `read_iot23_labeled(path)` / `iter_iot23_labeled(path, chunksize)` (IoT-23),
`read_zeek_json(path)` (gateway), `records_to_frame(lista_de_dicts)` (online),
`follow_jsonl(path)` (seguir um log que cresce).

Logs do gateway (escritos pelo Zeek em `logs/zeek/`, JSON, uma linha por registo, sem rotação):

* `conn.log`: registo final de cada ligação (igual ao do IoT-23);
* `conn_interim.log`: a cada `ZEEK_INTERIM_EVERY` (30 s), o estado **cumulativo** de cada
  ligação ainda aberta, com o mesmo `uid`. O registo final continua a ir para o `conn.log`.

Os timeouts do Zeek ficam nos valores por omissão, iguais aos do IoT-23 (ver `local.zeek`).

## §2 Features (`srsi.features.FeaturePipeline`, responsável: Rafael Silva)

```python
fp = FeaturePipeline(use_port=True).fit(df_treino)   # aprende min/max e categorias
X  = fp.transform(df)                                 # np.ndarray float, valores em [0,1]
fp.feature_names_                                     # lista ordenada de nomes
```

* Numéricas: as 8 de §1, NaN → 0, min-max (Eq. minmax) com min/max **do treino**; no
  `transform`, os valores fora do intervalo são cortados para [0,1].
* One-hot: `proto`, `service`, `conn_state`; categoria desconhecida → tudo a 0 (`handle_unknown="ignore"`).
* Porta de destino agrupada (one-hot): conhecida 0–1023, registada 1024–49151, efémera
  49152–65535. `use_port=False` retira-a (ensaio de controlo).
* Proibido usar: `ts`, `uid`, `orig_h`, `orig_p`, `resp_h`, `resp_p` em bruto, `label`,
  `detailed_label`, `capture`. `history` fica de fora na v1 (não foi prometida no relatório).
* Features derivadas extra só se entrarem para a pipeline (as mesmas no treino e no gateway).

## §3 Modelos guardados (`srsi.models`, responsáveis: Rafael Silva RF, Rafael Reis IF/AE)

```
models/<nome>/            ex.: rf, rf-sem-porta, iforest, autoencoder
  bundle.joblib           ModelBundle: features (§2) + scorer + threshold
  meta.json               gerado por save_bundle (versões, features, capturas de treino, FPR alvo)
```

* `bundle.score(df)` → `np.ndarray`, **maior = mais suspeito** em todos os modelos
  (adaptadores `RFScore`, `IFScore`, `AEScore`); `bundle.flag(df) = score >= threshold`.
* `threshold` fixado para a FPR alvo comum (proposta: **1 %** em benigno de validação). Para
  o autoencoder isto é o percentil 99 prometido para θ.
* `meta.json` deve incluir: `train_captures`, `val_captures`, `target_fpr`, `use_port`, `author`.
* Autoencoder com `sklearn.neural_network.MLPRegressor` (treino X → X, só benigno): evita
  instalar PyTorch no gateway.
* Versões fixas em `requirements.txt` (iguais às do gateway). Modelos até ~25 MB vão para o
  Git; maiores, para a pasta partilhada, com o `meta.json` no Git.
* `models/baseline-placeholder` (sem ML) serve para desenvolver §4–§5 antes de haver modelos.

## §4 Deteção online e decisão (`srsi.detector`, `srsi.decision`)

O detetor segue `conn.log` e `conn_interim.log`, converte com `records_to_frame`, aplica o
modelo escolhido (`--model models/rf`) e escreve uma linha por fluxo em
`logs/gateway/flows.jsonl`:

```json
{"t": 1763280001.62, "ts": 1763280001.5, "uid": "C2", "orig_h": "10.10.3.10", "resp_h": "185.244.25.235",
 "resp_p": 23, "proto": "tcp", "conn_state": "S0", "partial": false,
 "model": "rf", "score": 0.97, "threshold": 0.41, "flagged": true}
```

`t` = hora (epoch, s) em que o detetor processou o fluxo; `ts` = início do fluxo (Zeek).

Decisão (Eq. decisao): por `orig_h`, janela com os últimos `w` fluxos **distintos** (um `uid`
conta uma vez; um registo parcial é substituído pelo seguinte do mesmo `uid`); quarentena se
≥ `k` estiverem sinalizados. Só os IPs das sub-redes IoT (`10.10.0.0/16`) são candidatos.
Cada decisão vai para `logs/gateway/decisions.jsonl`:

```json
{"t": 1763280003.10, "orig_h": "10.10.3.10", "action": "quarantine", "model": "rf", "k": 3, "w": 10,
 "n_flagged": 3, "uids": ["C2", "C7", "C9"], "timeout_s": 300,
 "reason": "3 de 10 fluxos sinalizados (rf, limiar 0.41)", "t_applied": 1763280003.12}
```

`action` ∈ `quarantine` (nova), `renew` (já estava ou reincidiu), `release` (manual, caso de
uso 4). `t_applied` = hora a que o `nft` confirmou o elemento: é o **t_isolamento** de T_c.

## §5 Contenção (nftables, `srsi.containment`, responsável: Gonçalo)

Tabela `inet srsi`, set `quarantine` (`ipv4_addr`, `flags timeout`, expiração por omissão
`QUARANTINE_TIMEOUT`). Cadeia `forward`, por esta ordem (verificado no smoke test):

1. `ip saddr @quarantine drop` e `ip daddr @quarantine drop` (comentários `srsi-quarentena-*`);
2. `ct state established,related accept`;
3. `accept`.

Operações (com `nft` no gateway; o módulo Python chama estes comandos):

```
nft add element inet srsi quarantine '{ 10.10.3.10 timeout 300s }'   # quarentena / renovação*
nft delete element inet srsi quarantine '{ 10.10.3.10 }'              # libertação manual
nft -j list set inet srsi quarantine                                  # estado (com "expires")
```

\* Se o elemento já existir, `add` não renova o tempo: renovar = `delete` + `add` (ou
`nft reset`/`update` conforme a versão; a validar pelo Gonçalo).

O Zeek continua a ver o tráfego de um dispositivo em quarentena (o espelho é feito antes do
netfilter), por isso a renovação acontece naturalmente se ele continuar a ser sinalizado.

## §6 Experiências (`experiments/`, responsáveis: Afonso e Rafael Reis)

* Replay (Afonso): cada execução escreve em `logs/attacker/replay.jsonl`
  `{"t_start": ..., "t_end": ..., "pcap": ..., "capture": ..., "src_ip": "10.10.3.10", "speed": "original"}`.
  `t_start` = hora do primeiro pacote = **t_ataque**.
* Heartbeats dos nós: `logs/nodes/<host>.jsonl` `{"ts", "host", "target", "http_code", "ok"}`.
* Cada execução de cenário guarda tudo em `results/<cenário>/<modelo>/<run_id>/`
  (cópia dos logs + `run.json` com k, w, modelo, captura, seed) e o resumo em `summary.json`
  (T_c, T_deteção, T_resposta, n.º de quarentenas indevidas, CPU e memória médios e máximos do
  gateway, de `docker stats`).
* Resultados offline (§2–§3): `results/offline/<modelo>/metrics.json` com Precision, Recall,
  F1, FPR, PAM, AUC, a FPR alvo e as capturas de teste.

## Histórico

| Data | Alteração | Quem |
|---|---|---|
| 2026-11-16 | Versão inicial | Afonso Lopes |
| 2026-11-23 | Replay e preparação do dataset passam para o Afonso | Afonso Lopes |
