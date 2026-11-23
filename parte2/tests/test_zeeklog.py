import json
import threading
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from srsi.zeeklog import (CANONICAL_COLUMNS, follow_jsonl, iter_iot23_labeled, read_iot23_labeled,
                          read_zeek_json, records_to_frame)

DADOS = Path(__file__).parent / "dados"


def test_iot23_labeled():
    df = read_iot23_labeled(DADOS / "iot23_amostra.conn.log.labeled", capture="CTU-teste")
    assert list(df.columns) == CANONICAL_COLUMNS
    assert len(df) == 3
    assert df["label"].tolist() == [0, 1, 1]
    assert df["detailed_label"].tolist() == ["-", "PartOfAHorizontalPortScan", "C&C-HeartBeat"]
    assert df["service"].tolist() == ["-", "-", "dns"]
    assert np.isnan(df.loc[1, "duration"]) and df.loc[0, "duration"] == pytest.approx(3.139211)
    assert df["resp_p"].tolist() == [80, 80, 53]
    assert (df["capture"] == "CTU-teste").all() and not df["partial"].any()


def test_iot23_chunks_iguais_ao_total():
    path = DADOS / "iot23_amostra.conn.log.labeled"
    partes = pd.concat(list(iter_iot23_labeled(path, capture="x", chunksize=1)), ignore_index=True)
    pd.testing.assert_frame_equal(partes, read_iot23_labeled(path, capture="x"))


def test_gateway_json_mesmo_esquema():
    gw = read_zeek_json(DADOS / "gateway_amostra.conn.log")
    iot = read_iot23_labeled(DADOS / "iot23_amostra.conn.log.labeled")
    assert list(gw.columns) == list(iot.columns)
    assert dict(gw.dtypes) == dict(iot.dtypes)
    assert gw["label"].isna().all()
    assert gw.loc[1, "service"] == "-" and np.isnan(gw.loc[1, "duration"])


def test_interim_marcado_como_parcial(tmp_path):
    p = tmp_path / "conn_interim.log"
    p.write_text((DADOS / "gateway_amostra.conn.log").read_text())
    assert read_zeek_json(p)["partial"].all()


def test_records_vazio():
    assert list(records_to_frame([]).columns) == CANONICAL_COLUMNS


def test_follow_jsonl(tmp_path):
    p = tmp_path / "conn.log"

    def escritor():
        time.sleep(0.3)
        with open(p, "a") as fh:
            fh.write(json.dumps({"uid": "A"}) + "\n")
            fh.flush()
            fh.write('{"uid": "B"')          # linha incompleta ...
            fh.flush()
            time.sleep(0.3)
            fh.write("}\n")                  # ... só é devolvida quando termina

    threading.Thread(target=escritor).start()
    got = [r["uid"] for r in follow_jsonl(p, poll_s=0.05, stop_after_idle_s=1.0)]
    assert got == ["A", "B"]


def test_follow_jsonl_ignora_conteudo_antigo(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text('{"uid": "velho"}\n{"uid": "a_me')   # última linha a meio quando o detetor arranca

    def escritor():
        time.sleep(0.3)
        with open(p, "a") as fh:
            fh.write('io"}\n{"uid": "novo"}\n')

    threading.Thread(target=escritor).start()
    got = [r["uid"] for r in follow_jsonl(p, poll_s=0.05, stop_after_idle_s=1.0)]
    assert got == ["novo"]
