from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.neural_network import MLPRegressor

from srsi.models import (AEScore, IFScore, ModelBundle, RFScore, ScanLikeBaseline, load_bundle,
                         save_bundle)
from srsi.zeeklog import read_zeek_json

DADOS = Path(__file__).parent / "dados"


class FeaturesFalsas:
    """Substituto mínimo de srsi.features.FeaturePipeline para testar o contrato."""
    feature_names_ = ["orig_pkts", "resp_pkts"]

    def transform(self, df):
        return df[self.feature_names_].fillna(0).to_numpy(dtype=float) / 10.0


def test_baseline_roundtrip(tmp_path):
    df = read_zeek_json(DADOS / "gateway_amostra.conn.log")
    b = ModelBundle(name="baseline", scorer=ScanLikeBaseline(), threshold=0.5)
    save_bundle(b, tmp_path / "baseline", author="teste")
    b2 = load_bundle(tmp_path / "baseline")
    assert b2.flag(df).tolist() == [False, True]
    assert b2.meta["author"] == "teste" and b2.meta["features_hash"] is None


def test_convencao_maior_e_mais_suspeito(tmp_path):
    rng = np.random.default_rng(0)
    X_ben = rng.uniform(0, 0.3, size=(200, 2))
    X_mal = rng.uniform(0.7, 1.0, size=(200, 2))
    X = np.vstack([X_ben, X_mal]); y = np.r_[np.zeros(200), np.ones(200)]

    rf = RFScore(RandomForestClassifier(n_estimators=20, random_state=0).fit(X, y))
    iso = IFScore(IsolationForest(random_state=0).fit(X_ben))
    ae = AEScore(MLPRegressor(hidden_layer_sizes=(1,), max_iter=2000, random_state=0).fit(X_ben, X_ben))
    for s in (rf, iso, ae):
        assert s(X_mal).mean() > s(X_ben).mean(), type(s).__name__

    b = ModelBundle(name="rf", scorer=rf, threshold=0.5, features=FeaturesFalsas())
    save_bundle(b, tmp_path / "rf")
    assert load_bundle(tmp_path / "rf").meta["feature_names"] == ["orig_pkts", "resp_pkts"]
