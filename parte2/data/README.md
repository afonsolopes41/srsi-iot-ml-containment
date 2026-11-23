# data/ (não versionado, exceto este ficheiro e splits.json)

- `raw/` – IoT-23 tal como descarregado (versão *lighter* com os `conn.log.labeled`, mais os pcaps das capturas usadas no replay).
- `processed/` – um Parquet por captura no esquema canónico (`docs/interfaces.md` §1), gerado por `training/prepare_dataset.py`.
- `splits.json` – divisão treino/validação/teste **por captura** (versionado). Responsável: Afonso Lopes.
