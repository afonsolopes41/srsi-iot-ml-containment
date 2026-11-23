# Parte 2 – Protótipo

*Gateway* em contentores Docker que extrai fluxos com o Zeek, deteta dispositivos IoT
comprometidos com Random Forest, Isolation Forest e autoencoder, e põe-nos em quarentena
com nftables. Plano e divisão de tarefas: [`PLANO.md`](PLANO.md). Contratos entre módulos:
[`docs/interfaces.md`](docs/interfaces.md).

## Arrancar o banco de ensaio

Requisitos: Docker com Compose v2 (Linux, macOS, ou Windows com WSL2). No Windows, correr os
comandos dentro do WSL2.

```bash
cd parte2
docker compose up -d --build     # gateway, device1, device2, attacker, server
./scripts/smoke_test.sh          # verifica conn.log, ordem das regras, registos parciais e quarentena
docker compose down
```

Durante a execução:

```bash
tail -f logs/zeek/conn.log                                   # fluxos (JSON)
tail -f logs/nodes/device1.jsonl                             # heartbeat de um dispositivo
docker compose exec gateway nft list table inet srsi         # regras e set de quarentena
docker compose exec gateway nft add element inet srsi quarantine '{ 10.10.3.10 timeout 60s }'
```

Todas as redes Docker são `internal`: nenhum tráfego sai do computador e não é executado
*malware* real. O tráfego malicioso vem de capturas do IoT-23 reproduzidas com `tcpreplay`.

## Ambiente Python (treino e testes)

```bash
cd parte2
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest
python scripts/make_placeholder_model.py              # modelo provisório (sem ML) para testar a F3
```

## Estrutura

```
parte2/
  PLANO.md                 fases, divisão de tarefas, decisões em aberto
  docker-compose.yml       redes iot1–iot3 e ext, gateway e nós
  docs/interfaces.md       contratos: registo de fluxo, features, modelos, logs, nftables
  gateway/                 imagem do gateway (Afonso)
    entrypoint.sh            nftables, espelho tc → Zeek, rotas
    zeek/                    local.zeek, conn-interim.zeek (registos parciais)
    nft/srsi.nft             tabela inet srsi: set de quarentena e cadeia forward
  node/                    imagem comum: dispositivos, atacante e servidor
    replay/                  tcprewrite/tcpreplay (Afonso)
  src/srsi/                pacote Python partilhado (corre offline e no gateway)
    zeeklog.py               leitura do IoT-23 e dos logs do gateway (esquema canónico)
    features.py              FeaturePipeline (Rafael Silva)
    models/                  ModelBundle e adaptadores de score (RF: R. Silva; IF/AE: R. Reis)
    metrics.py               P, R, F1, FPR, PAM (Rafael Reis)
    detector.py              deteção online (Afonso)
    decision.py              janela k-de-w por dispositivo (Gonçalo)
    containment.py           operações sobre o set de quarentena (Gonçalo)
  training/                preparação de dados, treino, avaliação offline
  models/                  modelos treinados (bundle.joblib + meta.json)
  experiments/             cenários S1/S2/S3, T_c, CPU/memória
  results/                 métricas e figuras (versionadas)
  tests/                   pytest
  scripts/                 smoke_test.sh, utilitários
  relatorio/               relatório da Parte 2 e guião do vídeo
  data/, pcaps/, logs/     não versionados
```
