"""Resume uma execução de run_scenario.sh e grava summary.json na mesma pasta.

    python experiments/resumir_execucao.py results/S2/rf/run1

Métricas (Secção "Avaliação planeada"):
* t_ataque   = instante, no replay, do 1.º fluxo malicioso da janela (rótulos do IoT-23):
               t_start + (ts_1.º_malicioso - pcap_t0)
* T_deteção  = 1.º fluxo do dispositivo sinalizado pelo modelo (flows.jsonl, campo t) - t_ataque
* T_c        = entrada em quarentena (decisions.jsonl, t_applied) - t_ataque
* T_resposta = T_c - T_deteção
* fluxos sinalizados antes do ataque e quarentenas de outros IPs ou antes do ataque = indevidas
* CPU e memória do gateway (docker stats): média e máximo
Sem decisions.jsonl (decisão ainda não integrada) o T_c fica null.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pandas as pd

RAIZ = Path(__file__).resolve().parents[1]


def jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []


def mib(s: str) -> float:
    m = re.match(r"([\d.]+)\s*([KMG]i?B)", s)
    if not m:
        return float("nan")
    v, u = float(m.group(1)), m.group(2)[0]
    return v * {"K": 1 / 1024, "M": 1, "G": 1024}[u]


def main(pasta: str) -> dict:
    d = Path(pasta)
    run = json.loads((d / "run.json").read_text())
    rep = [r for r in (jsonl(next(d.glob("*/replay.jsonl"), d / "x"))) if r["capture"] == run["captura"]][-1]
    ip = rep["src_ip"]
    dur = rep["t_end"] - rep["t_start"]

    cap = pd.read_parquet(RAIZ / "data" / "processed" / f"{run['captura']}.parquet")
    janela = cap[(cap.ts >= rep["pcap_t0"]) & (cap.ts < rep["pcap_t0"] + dur)]
    mal = janela[janela.label == 1]
    t_ataque = rep["t_start"] + (mal.ts.min() - rep["pcap_t0"]) if len(mal) else None

    flows = [f for f in jsonl(d / "gateway" / "flows.jsonl") if f.get("orig_h") == ip]
    sinal = [f for f in flows if f["flagged"]]
    t_det = None
    if t_ataque is not None:
        dep = [f["t"] for f in sinal if f["t"] >= t_ataque]
        t_det = (min(dep) - t_ataque) if dep else None
    antes = [f for f in sinal if t_ataque is None or f["t"] < t_ataque]

    dec = [x for x in jsonl(d / "gateway" / "decisions.jsonl") if x.get("action") in ("quarantine", "renew")]
    q_disp = [x for x in dec if x["orig_h"] == ip and (t_ataque is not None and x["t_applied"] >= t_ataque)]
    indevidas = [x for x in dec if x not in q_disp]
    t_c = (min(x["t_applied"] for x in q_disp) - t_ataque) if q_disp else None

    st = pd.DataFrame(jsonl(d / "docker_stats.jsonl"))
    cpu = st["CPUPerc"].str.rstrip("%").astype(float) if len(st) else pd.Series(dtype=float)
    mem = st["MemUsage"].str.split("/").str[0].map(mib) if len(st) else pd.Series(dtype=float)

    r = lambda v, n=3: None if v is None or pd.isna(v) else round(float(v), n)
    s = {
        **run,
        "replay_s": r(dur, 1), "pacotes": rep.get("packets"),
        "fluxos_malicioso_janela": int(len(mal)), "t_ataque": r(t_ataque, 6),
        "fluxos_dispositivo": len(flows), "fluxos_sinalizados": len(sinal),
        "sinalizados_antes_do_ataque": len(antes),
        "T_deteccao_s": r(t_det), "T_c_s": r(t_c),
        "T_resposta_s": r(t_c - t_det) if t_c is not None and t_det is not None else None,
        "quarentenas_indevidas": len(indevidas),
        "decisao_integrada": (d / "gateway" / "decisions.jsonl").exists(),
        "cpu_media_pct": r(cpu.mean(), 2), "cpu_max_pct": r(cpu.max(), 2),
        "mem_media_mib": r(mem.mean(), 1), "mem_max_mib": r(mem.max(), 1),
    }
    (d / "summary.json").write_text(json.dumps(s, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(s, indent=2, ensure_ascii=False))
    return s


if __name__ == "__main__":
    main(sys.argv[1])
