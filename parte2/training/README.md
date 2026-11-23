# training/

Preparação de dados, treino e avaliação offline. Cada script grava um modelo em `models/<nome>/` (`docs/interfaces.md` §3) e as métricas em `results/offline/`.

| Script | Responsável |
|---|---|
| `prepare_dataset.py` | Afonso Lopes |
| `train_rf.py` | Rafael Silva |
| `train_iforest.py`, `train_autoencoder.py`, `evaluate_offline.py` | Rafael Reis |
