import json
from pathlib import Path

from srsi.detector import processar_lote
from srsi.models import ModelBundle, ScanLikeBaseline

DADOS = Path(__file__).parent / "dados"


def test_processar_lote_formato_flows_jsonl():
    recs = [json.loads(l) for l in (DADOS / "gateway_amostra.conn.log").read_text().splitlines()]
    b = ModelBundle(name="baseline", scorer=ScanLikeBaseline(), threshold=0.5)
    linhas = processar_lote(b, recs[:1], recs[1:])
    assert [l["uid"] for l in linhas] == ["C1", "C2"]
    assert [l["partial"] for l in linhas] == [False, True]
    assert [l["flagged"] for l in linhas] == [False, True]
    assert linhas[1]["resp_p"] == 23 and linhas[1]["orig_h"] == "10.10.3.10"
    json.dumps(linhas)  # tudo serializável
