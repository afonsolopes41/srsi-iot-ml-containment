# data/ (só `processed/`, `splits.json` e este ficheiro vão para o Git)

- `raw/` – IoT-23 tal como descarregado (versão *lighter* com os `conn.log.labeled`, mais os pcaps das capturas usadas no replay).
- `processed/` – um Parquet por captura no esquema canónico (`docs/interfaces.md` §1), gerado por `training/prepare_dataset.py` (versionado: 58 MB, 1,42 M fluxos amostrados de 325 M; `resumo.csv` tem os totais originais).
- `splits.json` – divisão treino/validação/teste **por captura** (versionado). Responsável: Afonso Lopes.
