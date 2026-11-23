#!/usr/bin/env bash
# Teste de fumo do esqueleto (Fase 0). Corre a partir de parte2/:
#     ./scripts/smoke_test.sh            (Linux, macOS ou WSL2 no Windows)
#
# Verifica, por esta ordem:
#   T1  o Zeek escreve conn.log em JSON com o tráfego de device1 -> server;
#   T2  a regra de quarentena está antes da regra established/related;
#   T3  ligações longas geram registos parciais em conn_interim.log;
#   T4  pôr device2 em quarentena corta-lhe o tráfego (incluindo a ligação já estabelecida)
#       e não afeta device1;
#   T5  a quarentena expira sozinha e o tráfego volta.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

DC="docker compose"
PASS=0; FAIL=0
ok()   { echo "  [OK]   $*"; PASS=$((PASS+1)); }
nok()  { echo "  [FALHA] $*"; FAIL=$((FAIL+1)); }
wait_for() {  # wait_for <segundos> <comando...>
  local t=$1; shift
  for ((i=0; i<t; i++)); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
curl_from() { $DC exec -T "$1" curl -s -o /dev/null -m 3 -w '%{http_code}' http://10.20.0.10/; }

echo "== A arrancar (docker compose up -d --build)"
mkdir -p logs
$DC up -d --build || { echo "docker compose falhou"; exit 1; }

echo "== T1: conn.log"
if wait_for 90 grep -q '"id.orig_h":"10.10.1.10"' logs/zeek/conn.log; then
  ok "conn.log tem ligações de device1 ($(wc -l < logs/zeek/conn.log) registos)"
else
  nok "conn.log sem ligações de device1 em 90 s (ver logs/gateway/gateway.log e '$DC logs gateway')"
fi

echo "== T2: ordem das regras"
RULES=$($DC exec -T gateway nft -a list chain inet srsi forward)
lq=$(grep -n 'srsi-quarentena-origem' <<<"$RULES" | cut -d: -f1)
le=$(grep -n 'srsi-estabelecidas' <<<"$RULES" | cut -d: -f1)
if [[ -n "$lq" && -n "$le" && "$lq" -lt "$le" ]]; then ok "quarentena (linha $lq) antes de established/related (linha $le)"
else nok "ordem das regras errada:"; echo "$RULES"; fi

echo "== T3: registos parciais (download lento de 2 MB em device2, ~2 min)"
$DC exec -d device2 curl -s -o /dev/null --limit-rate 16k http://10.20.0.10/big.bin
if wait_for 60 grep -q '"id.orig_h":"10.10.2.10"' logs/zeek/conn_interim.log; then
  ok "conn_interim.log tem registos parciais da ligação de device2"
else
  nok "sem registos parciais em 60 s (ver conn-interim.zeek)"
fi

echo "== T4: quarentena de device2 (20 s)"
[[ "$(curl_from device2)" == "200" ]] && ok "antes: device2 chega ao servidor" || nok "antes: device2 já não chegava ao servidor"
$DC exec -T gateway nft add element inet srsi quarantine '{ 10.10.2.10 timeout 20s }'
sleep 3
code2=$(curl_from device2); code1=$(curl_from device1)
[[ "$code2" != "200" ]] && ok "depois: device2 bloqueado (http_code=$code2)" || nok "depois: device2 continua a chegar ao servidor"
[[ "$code1" == "200" ]] && ok "depois: device1 não é afetado" || nok "depois: device1 também ficou bloqueado"
cnt=$($DC exec -T gateway nft list chain inet srsi forward | grep -E 'srsi-quarentena-(origem|destino)' \
      | grep -oE 'packets [0-9]+' | awk '{s+=$2} END{print s+0}')
[[ "$cnt" -gt 0 ]] && ok "regras de quarentena descartaram $cnt pacotes (inclui a ligação já estabelecida)" \
                   || nok "contadores da quarentena a zero"

echo "== T5: expiração"
if wait_for 30 bash -c "[[ \$($DC exec -T device2 curl -s -o /dev/null -m 2 -w '%{http_code}' http://10.20.0.10/) == 200 ]]"; then
  ok "quarentena expirou e device2 voltou a chegar ao servidor"
else
  nok "device2 continua bloqueado 30 s depois"
fi
$DC exec -T device2 pkill curl >/dev/null 2>&1 || true

echo
echo "Resultado: $PASS OK, $FAIL falhas.  (Para parar: docker compose down)"
[[ $FAIL -eq 0 ]]
