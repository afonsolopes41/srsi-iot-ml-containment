"""Converte os conn.log.labeled do IoT-23 em Parquet no esquema canónico (docs/interfaces.md §1).

Uso (a partir de parte2/):
    python training/prepare_dataset.py --raw data/raw/iot_23_datasets_full --out data/processed

Para cada captura (pasta CTU-*) escreve ``data/processed/<captura>.parquet`` e, no fim,
``data/processed/resumo.csv`` com o n.º de fluxos lidos e guardados por rótulo detalhado.

Amostragem: as maiores capturas têm dezenas de milhões de fluxos. Por cada par
(captura, detailed_label) guardam-se no máximo ``--max-por-classe`` fluxos, escolhidos ao
acaso de forma uniforme e reprodutível (semente fixa). Assim as classes raras (ex. C&C) ficam
inteiras e as dominantes (ex. PartOfAHorizontalPortScan) não esmagam as outras. Os totais
originais ficam no resumo, para o relatório.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from srsi.zeeklog import iter_iot23_labeled  # noqa: E402


def amostrar_captura(path: Path, captura: str, max_por_classe: int, seed: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Amostragem por prioridades aleatórias: fica com os ``max_por_classe`` fluxos de menor
    chave aleatória em cada classe, o que equivale a uma amostra uniforme sem reposição."""
    rng = np.random.default_rng(seed)
    guardados: pd.DataFrame | None = None
    contagens: dict[tuple, int] = {}
    for chunk in iter_iot23_labeled(path, capture=captura):
        chunk["_k"] = rng.random(len(chunk))
        for key, n in chunk.groupby(["label", "detailed_label"], dropna=False).size().items():
            contagens[key] = contagens.get(key, 0) + int(n)
        juntos = chunk if guardados is None else pd.concat([guardados, chunk], ignore_index=True)
        guardados = (juntos.sort_values("_k")
                     .groupby(["label", "detailed_label"], dropna=False, sort=False)
                     .head(max_por_classe))
    if guardados is None:
        return pd.DataFrame(), pd.DataFrame()
    guardados = guardados.sort_values("ts").drop(columns="_k").reset_index(drop=True)
    resumo = pd.DataFrame(
        [{"capture": captura, "label": k[0], "detailed_label": k[1], "n_original": v}
         for k, v in contagens.items()])
    n_guard = guardados.groupby(["label", "detailed_label"], dropna=False).size().rename("n_guardado")
    resumo = resumo.merge(n_guard.reset_index(), on=["label", "detailed_label"], how="left")
    return guardados, resumo


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw", type=Path, required=True, help="pasta com as capturas CTU-* do IoT-23")
    ap.add_argument("--out", type=Path, default=Path("data/processed"))
    ap.add_argument("--max-por-classe", type=int, default=50_000)
    ap.add_argument("--seed", type=int, default=23)
    ap.add_argument("--so", nargs="*", default=None, help="processar só estas capturas")
    args = ap.parse_args()

    logs = sorted(args.raw.glob("CTU-*/bro/conn.log.labeled"))
    if args.so:
        logs = [p for p in logs if p.parent.parent.name in args.so]
    if not logs:
        sys.exit(f"Nenhum CTU-*/bro/conn.log.labeled em {args.raw}")
    args.out.mkdir(parents=True, exist_ok=True)

    resumos = []
    for i, path in enumerate(logs, 1):
        captura = path.parent.parent.name
        destino = args.out / f"{captura}.parquet"
        print(f"[{i}/{len(logs)}] {captura} ({path.stat().st_size / 1e6:.0f} MB)", flush=True)
        df, resumo = amostrar_captura(path, captura, args.max_por_classe, args.seed)
        df.to_parquet(destino, index=False)
        resumos.append(resumo)
        print(f"        {resumo['n_original'].sum():,} fluxos -> {len(df):,} guardados", flush=True)

    pd.concat(resumos, ignore_index=True).to_csv(args.out / "resumo.csv", index=False)
    print(f"Resumo em {args.out / 'resumo.csv'}")


if __name__ == "__main__":
    main()
