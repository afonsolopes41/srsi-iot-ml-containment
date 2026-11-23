"""Cria models/baseline-placeholder: um "modelo" sem ML que sinaliza tentativas sem resposta.

Serve só para desenvolver e testar a deteção online, a decisão e a contenção antes de os
modelos reais existirem (docs/interfaces.md §3). Uso, a partir de parte2/:
    python scripts/make_placeholder_model.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from srsi.models import ModelBundle, ScanLikeBaseline, save_bundle  # noqa: E402

out = Path(__file__).resolve().parents[1] / "models" / "baseline-placeholder"
save_bundle(ModelBundle(name="baseline-placeholder", scorer=ScanLikeBaseline(), threshold=0.5),
            out, notes="Marcador de posição sem ML (conn_state sem resposta). Não usar nos resultados.")
print(f"gravado em {out}")
