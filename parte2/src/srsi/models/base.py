"""Contrato dos modelos guardados (docs/interfaces.md §3).

Um modelo treinado é uma pasta ``models/<nome>/`` com:

* ``bundle.joblib`` – um ``ModelBundle`` (pipeline de features + estimador + limiar);
* ``meta.json``     – metadados legíveis (gerados por ``save_bundle``).

No gateway, o detetor só faz::

    b = load_bundle("models/rf")
    s = b.score(df)          # df no esquema canónico (srsi.zeeklog); maior = mais suspeito
    y = s >= b.threshold     # fluxo sinalizado (y_j da Eq. decisao)

Os três modelos usam a mesma convenção de score, através dos adaptadores abaixo, para que o
limiar se possa ajustar à mesma FPR em todos (Secção "Avaliação planeada").
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import platform
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import joblib
import numpy as np
import pandas as pd
import sklearn

BUNDLE_FORMAT = 1


class FeatureTransformer(Protocol):
    """O que ``srsi.features.FeaturePipeline`` tem de implementar (Rafael Silva)."""
    feature_names_: list[str]

    def transform(self, df: pd.DataFrame) -> np.ndarray: ...


# --------------------------------------------------------------------------- adaptadores de score

class RFScore:
    """Random Forest: probabilidade da classe maliciosa (Eq. rf)."""
    def __init__(self, estimator): self.estimator = estimator
    def __call__(self, X: np.ndarray) -> np.ndarray:
        classes = list(self.estimator.classes_)
        return self.estimator.predict_proba(X)[:, classes.index(1)]


class IFScore:
    """Isolation Forest: simétrico de score_samples (maior = mais anómalo, Eq. iforest)."""
    def __init__(self, estimator): self.estimator = estimator
    def __call__(self, X: np.ndarray) -> np.ndarray:
        return -self.estimator.score_samples(X)


class AEScore:
    """Autoencoder (MLPRegressor treinado X -> X): erro quadrático médio de reconstrução (Eq. ae)."""
    def __init__(self, estimator): self.estimator = estimator
    def __call__(self, X: np.ndarray) -> np.ndarray:
        return np.mean((X - self.estimator.predict(X)) ** 2, axis=1)


class ScanLikeBaseline:
    """Marcador de posição SEM ML, para desenvolver a decisão/contenção antes de haver modelos.

    Sinaliza tentativas sem resposta (S0, REJ, RSTOS0, SH, OTH) — o padrão de um varrimento.
    Trabalha diretamente sobre o DataFrame canónico (``features=None``). NÃO é o baseline do
    relatório (esse é o detetor de varrimentos do próprio Zeek).
    """
    STATES = {"S0", "REJ", "RSTOS0", "SH", "OTH"}
    def __call__(self, df: pd.DataFrame) -> np.ndarray:
        return df["conn_state"].isin(self.STATES).to_numpy(dtype=float)


# --------------------------------------------------------------------------- bundle

@dataclass
class ModelBundle:
    name: str                      # "rf" | "iforest" | "autoencoder" | "baseline" | ...
    scorer: Any                    # um dos adaptadores acima (callable)
    threshold: float               # fluxo sinalizado se score >= threshold
    features: FeatureTransformer | None = None   # None => scorer recebe o DataFrame canónico
    meta: dict = field(default_factory=dict)     # ver save_bundle

    def score(self, df: pd.DataFrame) -> np.ndarray:
        if len(df) == 0:
            return np.empty(0)
        X = df if self.features is None else self.features.transform(df)
        return np.asarray(self.scorer(X), dtype=float)

    def flag(self, df: pd.DataFrame) -> np.ndarray:
        return self.score(df) >= self.threshold


def _features_hash(features: FeatureTransformer | None) -> str | None:
    if features is None:
        return None
    names = ",".join(getattr(features, "feature_names_", []))
    return hashlib.sha256(names.encode()).hexdigest()[:12]


def save_bundle(bundle: ModelBundle, out_dir: str | Path, **meta: Any) -> Path:
    """Grava ``bundle.joblib`` + ``meta.json``. Campos recomendados em ``meta``:

    ``train_captures``, ``val_captures``, ``target_fpr``, ``threshold_rule`` (ex. "p99 benigno val"),
    ``use_port`` (bool), ``author``, ``notes``.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    bundle.meta = {
        "format": BUNDLE_FORMAT,
        "name": bundle.name,
        "threshold": float(bundle.threshold),
        "feature_names": list(getattr(bundle.features, "feature_names_", []) or []),
        "features_hash": _features_hash(bundle.features),
        "sklearn": sklearn.__version__,
        "python": platform.python_version(),
        "created": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        **bundle.meta,
        **meta,
    }
    joblib.dump(bundle, out / "bundle.joblib", compress=3)
    (out / "meta.json").write_text(json.dumps(bundle.meta, indent=2, ensure_ascii=False) + "\n",
                                   encoding="utf-8")
    return out


def load_bundle(model_dir: str | Path) -> ModelBundle:
    model_dir = Path(model_dir)
    bundle: ModelBundle = joblib.load(model_dir / "bundle.joblib")
    v = bundle.meta.get("sklearn")
    if v and v != sklearn.__version__:
        warnings.warn(f"{model_dir}: treinado com scikit-learn {v}, a correr com "
                      f"{sklearn.__version__} (ver requirements.txt)")
    return bundle
