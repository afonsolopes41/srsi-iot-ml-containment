import importlib.util
from pathlib import Path

DADOS = Path(__file__).parent / "dados"
spec = importlib.util.spec_from_file_location(
    "prepare_dataset", Path(__file__).parents[1] / "training" / "prepare_dataset.py")
prep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prep)


def test_amostragem_por_classe():
    path = DADOS / "iot23_amostra.conn.log.labeled"
    df, resumo = prep.amostrar_captura(path, "CTU-teste", max_por_classe=1, seed=0)
    # 3 classes diferentes na amostra, 1 fluxo cada
    assert len(df) == 3 and resumo["n_original"].sum() == 3
    assert (resumo["n_guardado"] == 1).all()
    assert df["ts"].is_monotonic_increasing
    df2, _ = prep.amostrar_captura(path, "CTU-teste", max_por_classe=1, seed=0)
    assert df.equals(df2)  # reprodutível
