"""Valida o replay: compara os fluxos que o gateway viu com os do conn.log original do IoT-23.

Uso (a partir de parte2/, depois de um replay):
    python experiments/comparar_replay.py --captura CTU-IoT-Malware-Capture-34-1

Lê a última linha de logs/<host>/replay.jsonl dessa captura (pcap_t0, t_start, t_end, IPs),
recorta no IoT-23 (data/processed) a mesma janela da captura original e, no logs/zeek/conn.log,
os fluxos do dispositivo durante o replay. Escreve results/replay/<captura>.md com a comparação
(n.º de fluxos, protocolos, estados, portas, medianas). É a prova de fidelidade do replay
(validação do protótipo).

Nota: o IoT-23 de teste não está amostrado, por isso as contagens são comparáveis.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "src"))
from srsi.zeeklog import read_zeek_json  # noqa: E402

NUM = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]


def ultimo_replay(captura: str) -> dict:
    linhas = []
    for f in (RAIZ / "logs").glob("*/replay.jsonl"):
        linhas += [json.loads(l) for l in f.read_text().splitlines() if l.strip()]
    linhas = [l for l in linhas if l["capture"] == captura]
    if not linhas:
        sys.exit(f"Não há replay de {captura} em logs/*/replay.jsonl")
    return max(linhas, key=lambda l: l["t_start"])


def resumo(df: pd.DataFrame) -> dict:
    return {
        "fluxos": len(df),
        "proto": df["proto"].value_counts().to_dict(),
        "conn_state (top 6)": df["conn_state"].value_counts().head(6).to_dict(),
        "porta destino (top 5)": {int(k): int(v) for k, v in df["resp_p"].value_counts().head(5).items()},
        **{f"mediana {c}": round(float(df[c].median()), 3) if df[c].notna().any() else None for c in NUM},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--captura", required=True)
    ap.add_argument("--margem", type=float, default=120.0,
                    help="segundos a mais depois do fim do replay (o Zeek escreve as ligações quando acabam)")
    a = ap.parse_args()

    r = ultimo_replay(a.captura)
    dur = r["t_end"] - r["t_start"]

    orig = pd.read_parquet(RAIZ / "data" / "processed" / f"{a.captura}.parquet")
    orig = orig[(orig.ts >= r["pcap_t0"]) & (orig.ts < r["pcap_t0"] + dur)]
    orig = orig[(orig.orig_h == r["ip_original"]) | (orig.resp_h == r["ip_original"])]

    gw = read_zeek_json(RAIZ / "logs" / "zeek" / "conn.log")
    gw = gw[(gw.ts >= r["t_start"] - 1) & (gw.ts < r["t_end"] + a.margem)]
    gw = gw[(gw.orig_h == r["src_ip"]) | (gw.resp_h == r["src_ip"])]
    # o heartbeat HTTP ao servidor não existe na captura original
    gw = gw[~((gw.resp_h == "10.20.0.10") & (gw.resp_p == 80))]

    ro, rg = resumo(orig), resumo(gw)
    linhas = [f"# Replay de {a.captura}", "",
              f"- pcap: `{r['pcap']}`, {r['packets']} pacotes, {dur:.0f} s à velocidade original",
              f"- IP {r['ip_original']} reescrito para {r['src_ip']}", "",
              "| | IoT-23 original | Gateway (replay) |", "|---|---|---|"]
    for k in ro:
        linhas.append(f"| {k} | {ro[k]} | {rg[k]} |")
    if len(orig):
        linhas += ["", f"Razão de fluxos gateway/original: **{len(gw) / len(orig):.2f}**"]
    out = RAIZ / "results" / "replay" / f"{a.captura}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(linhas) + "\n", encoding="utf-8")
    print("\n".join(linhas))
    print(f"\nGravado em {out}")


if __name__ == "__main__":
    main()
