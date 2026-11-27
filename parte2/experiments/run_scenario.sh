#!/usr/bin/env bash
# Corre UMA execução de um cenário no protótipo e guarda tudo em results/<cenário>/<modelo>/<run>/.
#
# Uso (a partir de parte2/, no Git Bash):
#   ./experiments/run_scenario.sh S2 baseline-placeholder 1
#   ./experiments/run_scenario.sh S3 rf 2
#
#   <cenário>  S1 | S2 | S3            (definidos em CENARIOS abaixo)
#   <modelo>   pasta em models/        (o detetor do gateway usa-a)
#   <run>      número da repetição
#
# Passos: reinicia a rede com o modelo escolhido (logs limpos) -> espera que o Zeek arranque ->
# recolhe CPU/memória do gateway de 2 em 2 s -> faz o replay no nó certo -> espera MARGEM s
# (o Zeek só escreve as ligações quando acabam) -> copia os logs -> calcula o resumo
# (T_deteção, T_c, quarentenas indevidas, CPU, memória) com resumir_execucao.py.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

CEN=${1:?cenário (S1/S2/S3)}; MODELO=${2:?modelo (pasta em models/)}; RUN=${3:?n.º da repetição}
MARGEM=${MARGEM:-120}
PY=${PY:-.venv/Scripts/python.exe}; [[ -x "$PY" ]] || PY=python

#            nó        pcap (em pcaps/)               IP original        captura IoT-23
case "$CEN" in
  S1) NO=device1;  PCAP=s1_somfy_60min.pcap;       IP=192.168.1.158;   CAP=CTU-Honeypot-Capture-7-1 ;;
  S2) NO=attacker; PCAP=s2_mirai_34-1_20min.pcap;  IP=192.168.1.195;   CAP=CTU-IoT-Malware-Capture-34-1 ;;
  S3) NO=attacker; PCAP=s3_torii_20-1_15min.pcap;  IP=192.168.100.103; CAP=CTU-IoT-Malware-Capture-20-1 ;;
  *) echo "cenário desconhecido: $CEN" >&2; exit 1 ;;
esac
[[ -d "models/$MODELO" ]] || { echo "não existe models/$MODELO" >&2; exit 1; }
[[ -f "pcaps/$PCAP" ]]   || { echo "não existe pcaps/$PCAP" >&2; exit 1; }

DEST="results/$CEN/$MODELO/run$RUN"
echo "== $CEN | modelo $MODELO | repetição $RUN -> $DEST"

docker compose down >/dev/null 2>&1 || true
rm -rf logs && mkdir -p logs
DETECTOR_MODEL="/opt/srsi/models/$MODELO" docker compose up -d >/dev/null
echo "   a aguardar o arranque do Zeek..."
for _ in $(seq 60); do grep -q "listening on zeekmon" <(docker compose logs gateway 2>&1) && break; sleep 1; done
sleep 5

# CPU e memória do gateway de 2 em 2 s, em segundo plano
( while true; do
    docker stats --no-stream --format '{{json .}}' srsi-gateway-1 2>/dev/null \
      | sed "s/^{/{\"t\":$(date +%s),/" >> logs/docker_stats.jsonl
    sleep 2
  done ) &
STATS_PID=$!
trap 'kill $STATS_PID 2>/dev/null || true' EXIT

docker compose exec -T "$NO" bash /opt/replay/replay.sh "/pcaps/$PCAP" "$IP" "$CAP"
echo "   replay terminado; a esperar ${MARGEM}s pelas últimas ligações..."
sleep "$MARGEM"
kill $STATS_PID 2>/dev/null || true

rm -rf "$DEST" && mkdir -p "$DEST"
cp -r logs/. "$DEST/"
printf '{"cenario":"%s","modelo":"%s","run":%s,"no":"%s","pcap":"%s","captura":"%s","margem_s":%s}\n' \
  "$CEN" "$MODELO" "$RUN" "$NO" "$PCAP" "$CAP" "$MARGEM" > "$DEST/run.json"
"$PY" experiments/resumir_execucao.py "$DEST"
