"""Deteção em tempo real no gateway (módulo 2 da arquitetura; docs/interfaces.md §4).

Segue o conn.log e o conn_interim.log do Zeek, converte cada registo para o esquema canónico,
aplica o modelo e escreve uma linha por fluxo em flows.jsonl. A decisão (k de w) lê esse
ficheiro.

    python -m srsi.detector --model /opt/srsi/models/rf

No gateway arranca sozinho se a variável DETECTOR_MODEL estiver definida (entrypoint.sh).
"""
from __future__ import annotations

import argparse
import json
import queue
import threading
import time
from pathlib import Path

import numpy as np

from .models import load_bundle
from .zeeklog import follow_jsonl, records_to_frame

CAMPOS_SAIDA = ["ts", "uid", "orig_h", "resp_h", "resp_p", "proto", "conn_state", "partial"]


def _seguir(path: Path, partial: bool, fila: queue.Queue, from_start: bool) -> None:
    for rec in follow_jsonl(path, from_start=from_start):
        fila.put((partial, rec))


def _json_valor(v):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    if isinstance(v, (np.integer,)):
        return int(v)
    if isinstance(v, (np.floating,)):
        return float(v)
    if isinstance(v, (np.bool_,)):
        return bool(v)
    try:
        import pandas as pd
        if v is pd.NA:
            return None
    except ImportError:  # pragma: no cover
        pass
    return v


def processar_lote(bundle, recs_final: list[dict], recs_parcial: list[dict]) -> list[dict]:
    """Aplica o modelo a um lote e devolve as linhas de flows.jsonl (sem ``t``)."""
    linhas = []
    for recs, partial in ((recs_final, False), (recs_parcial, True)):
        if not recs:
            continue
        df = records_to_frame(recs, partial=partial)
        scores = bundle.score(df)
        for row, s in zip(df[CAMPOS_SAIDA].itertuples(index=False), scores):
            d = {k: _json_valor(v) for k, v in zip(CAMPOS_SAIDA, row)}
            d.update(model=bundle.name, score=float(s), threshold=float(bundle.threshold),
                     flagged=bool(s >= bundle.threshold))
            linhas.append(d)
    return linhas


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True, type=Path, help="pasta do modelo (models/<nome>)")
    ap.add_argument("--zeek-dir", type=Path, default=Path("/logs/zeek"))
    ap.add_argument("--out", type=Path, default=Path("/logs/gateway/flows.jsonl"))
    ap.add_argument("--lote-s", type=float, default=0.2, help="intervalo máximo entre lotes")
    ap.add_argument("--desde-inicio", action="store_true", help="ler também o que já está nos logs")
    args = ap.parse_args(argv)

    bundle = load_bundle(args.model)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fila: queue.Queue = queue.Queue()
    for nome, parcial in (("conn.log", False), ("conn_interim.log", True)):
        threading.Thread(target=_seguir, args=(args.zeek_dir / nome, parcial, fila, args.desde_inicio),
                         daemon=True).start()
    print(f"[detetor] modelo={bundle.name} limiar={bundle.threshold} -> {args.out}", flush=True)

    with open(args.out, "a", encoding="utf-8") as out:
        while True:
            finais, parciais = [], []
            try:
                partial, rec = fila.get(timeout=args.lote_s)
                (parciais if partial else finais).append(rec)
                while True:  # esvaziar o que já chegou
                    partial, rec = fila.get_nowait()
                    (parciais if partial else finais).append(rec)
            except queue.Empty:
                pass
            if not (finais or parciais):
                continue
            agora = time.time()
            for linha in processar_lote(bundle, finais, parciais):
                out.write(json.dumps({"t": round(agora, 6), **linha}) + "\n")
            out.flush()


if __name__ == "__main__":
    main()
