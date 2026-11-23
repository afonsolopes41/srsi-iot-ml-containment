"""Leitura de registos de ligações do Zeek para o esquema canónico (docs/interfaces.md §1).

Há três origens, todas convertidas para o MESMO DataFrame:

* IoT-23 ``conn.log.labeled`` (TSV do Zeek com 3 colunas extra de rótulo) -> treino/teste offline;
* ``conn.log`` do gateway (JSON, uma linha por registo)                    -> protótipo;
* ``conn_interim.log`` do gateway (JSON, registos parciais)                -> protótipo, ``partial=True``.

As features (``srsi.features``) só podem depender das colunas de ``CANONICAL_COLUMNS``.
"""
from __future__ import annotations

import io
import json
import os
import time
from collections.abc import Iterator
from pathlib import Path

import numpy as np
import pandas as pd

# Campos do Zeek -> nome canónico (sem pontos, para facilitar o pandas).
ZEEK_TO_CANONICAL = {
    "ts": "ts",
    "uid": "uid",
    "id.orig_h": "orig_h",
    "id.orig_p": "orig_p",
    "id.resp_h": "resp_h",
    "id.resp_p": "resp_p",
    "proto": "proto",
    "service": "service",
    "duration": "duration",
    "orig_bytes": "orig_bytes",
    "resp_bytes": "resp_bytes",
    "conn_state": "conn_state",
    "missed_bytes": "missed_bytes",
    "history": "history",
    "orig_pkts": "orig_pkts",
    "orig_ip_bytes": "orig_ip_bytes",
    "resp_pkts": "resp_pkts",
    "resp_ip_bytes": "resp_ip_bytes",
}

#: Identificação do fluxo. NUNCA entram nas features (Secção "Modelos de deteção").
ID_COLUMNS = ["ts", "uid", "orig_h", "orig_p", "resp_h"]
#: Numéricas (float, NaN quando o Zeek não as preenche, ex.: duration de uma tentativa S0).
NUMERIC_COLUMNS = [
    "duration", "orig_bytes", "resp_bytes", "missed_bytes",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
]
#: Categóricas (str; "-" quando não há valor).
CATEGORICAL_COLUMNS = ["proto", "service", "conn_state", "history"]
#: Metadados acrescentados por este módulo.
META_COLUMNS = ["resp_p", "label", "detailed_label", "capture", "partial"]

CANONICAL_COLUMNS = ID_COLUMNS + ["resp_p"] + CATEGORICAL_COLUMNS + NUMERIC_COLUMNS + [
    "label", "detailed_label", "capture", "partial",
]

UNSET = "-"


def _finalize(df: pd.DataFrame, *, capture: str | None, partial: bool) -> pd.DataFrame:
    """Tipos e colunas finais, por esta ordem: CANONICAL_COLUMNS."""
    for col in ID_COLUMNS + ["resp_p"] + CATEGORICAL_COLUMNS + NUMERIC_COLUMNS:
        if col not in df.columns:
            df[col] = np.nan
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce").astype("float64")
    for col in ["orig_p", "resp_p"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int32")
    for col in NUMERIC_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce").astype("float64")
    for col in CATEGORICAL_COLUMNS + ["uid", "orig_h", "resp_h"]:
        df[col] = df[col].astype("object").where(df[col].notna(), UNSET).astype(str)
        df[col] = df[col].replace({"(empty)": UNSET, "": UNSET})
    if "label" not in df.columns:
        df["label"] = pd.array([pd.NA] * len(df), dtype="Int8")
    if "detailed_label" not in df.columns:
        df["detailed_label"] = UNSET
    df["capture"] = capture if capture is not None else UNSET
    df["partial"] = bool(partial)
    return df[CANONICAL_COLUMNS].reset_index(drop=True)


# --------------------------------------------------------------------------- IoT-23 (TSV)

def _iot23_header(path: Path) -> tuple[list[str], int]:
    """Lê o cabeçalho #fields. Devolve (nomes das colunas, n.º de linhas de comentário iniciais)."""
    fields: list[str] | None = None
    n_comments = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.startswith("#"):
                break
            n_comments += 1
            if line.startswith("#fields"):
                # No IoT-23 as 3 últimas colunas vêm separadas por 3 espaços em vez de TAB.
                fields = line.rstrip("\n").replace("   ", "\t").split("\t")[1:]
    if fields is None:
        raise ValueError(f"{path}: cabeçalho #fields não encontrado")
    return fields, n_comments


def _label_to_int(s: pd.Series) -> pd.Series:
    low = s.astype(str).str.strip().str.lower()
    out = pd.Series(pd.NA, index=s.index, dtype="Int8")
    out[low.eq("benign")] = 0
    out[low.str.startswith("malicious")] = 1
    return out


def iter_iot23_labeled(path: str | os.PathLike, capture: str | None = None,
                       chunksize: int = 500_000) -> Iterator[pd.DataFrame]:
    """Lê um ``conn.log.labeled`` do IoT-23 aos blocos (os maiores têm dezenas de milhões de linhas).

    ``capture`` identifica a captura (ex.: ``"CTU-IoT-Malware-Capture-1-1"``); por omissão é o
    nome da pasta que contém ``bro/`` ou o próprio ficheiro. É a chave da divisão treino/teste.
    """
    path = Path(path)
    if capture is None:
        capture = path.parent.parent.name if path.parent.name == "bro" else path.stem
    fields, n_comments = _iot23_header(path)
    n_main = len(fields) - 2  # as últimas 3 (tunnel_parents, label, detailed-label) chegam numa só coluna
    names = fields[:n_main - 1] + ["_tail"]
    reader = pd.read_csv(
        path, sep="\t", names=names, skiprows=n_comments, comment="#", dtype=str,
        na_values=[UNSET], keep_default_na=False, chunksize=chunksize, engine="c",
    )
    for chunk in reader:
        tail = chunk.pop("_tail").fillna("").str.split(r"\s{2,}|\t", n=2, expand=True, regex=True)
        tail = tail.reindex(columns=[0, 1, 2])
        chunk["label"] = _label_to_int(tail[1])
        det = tail[2].fillna(UNSET).str.strip()
        chunk["detailed_label"] = det.where(det.ne(""), UNSET)
        chunk = chunk.rename(columns=ZEEK_TO_CANONICAL)
        yield _finalize(chunk, capture=capture, partial=False)


def read_iot23_labeled(path: str | os.PathLike, capture: str | None = None) -> pd.DataFrame:
    """Lê um ``conn.log.labeled`` inteiro (ver ``iter_iot23_labeled``)."""
    parts = list(iter_iot23_labeled(path, capture=capture))
    return pd.concat(parts, ignore_index=True) if parts else _finalize(
        pd.DataFrame(), capture=capture, partial=False)


# --------------------------------------------------------------------------- gateway (JSON)

def records_to_frame(records: list[dict], *, partial: bool = False,
                     capture: str | None = None) -> pd.DataFrame:
    """Converte registos JSON do Zeek (dicts) para o esquema canónico."""
    df = pd.DataFrame.from_records(records) if records else pd.DataFrame()
    df = df.rename(columns=ZEEK_TO_CANONICAL)
    return _finalize(df, capture=capture, partial=partial)


def read_zeek_json(path: str | os.PathLike, *, partial: bool | None = None,
                   capture: str | None = None) -> pd.DataFrame:
    """Lê um log JSON do gateway. ``partial`` é inferido do nome (``conn_interim*``)."""
    path = Path(path)
    if partial is None:
        partial = path.name.startswith("conn_interim")
    with open(path, encoding="utf-8") as fh:
        recs = [json.loads(line) for line in fh if line.strip()]
    return records_to_frame(recs, partial=partial, capture=capture)


def follow_jsonl(path: str | os.PathLike, *, poll_s: float = 0.2,
                 from_start: bool = False, stop_after_idle_s: float | None = None) -> Iterator[dict]:
    """Segue um ficheiro JSONL que vai crescendo (``tail -F``), devolvendo um dict por linha.

    Funciona mesmo que o ficheiro ainda não exista ou seja recriado (reinício do Zeek).
    ``stop_after_idle_s`` serve para testes: termina se não houver linhas novas durante esse tempo.
    """
    path = Path(path)
    fh: io.TextIOWrapper | None = None
    inode = None
    buf = ""
    idle = 0.0
    # Se o ficheiro ainda não existe, tudo o que lá aparecer é novo: ler desde o início.
    skip_existing = (not from_start) and path.exists()
    drop_partial = False
    while True:
        if fh is None:
            if path.exists():
                fh = open(path, encoding="utf-8", newline="")
                inode = os.fstat(fh.fileno()).st_ino
                if skip_existing:
                    end = fh.seek(0, os.SEEK_END)
                    if end > 0:  # se a última linha está a meio, descartá-la até ao próximo \n
                        fh.seek(end - 1)
                        drop_partial = fh.read(1) != "\n"
                skip_existing = False  # depois de um recriar, ler o novo ficheiro desde o início
        if fh is not None:
            chunk = fh.read()
            if chunk:
                idle = 0.0
                buf += chunk
                if drop_partial:
                    if "\n" not in buf:
                        continue
                    buf = buf.split("\n", 1)[1]
                    drop_partial = False
                *lines, buf = buf.split("\n")
                for line in lines:
                    if line.strip():
                        yield json.loads(line)
                continue
            try:
                st = os.stat(path)
                if st.st_ino != inode or st.st_size < fh.tell():
                    fh.close(); fh = None; buf = ""; drop_partial = False
                    continue
            except FileNotFoundError:
                fh.close(); fh = None; buf = ""; drop_partial = False
        time.sleep(poll_s)
        idle += poll_s
        if stop_after_idle_s is not None and idle >= stop_after_idle_s:
            return
