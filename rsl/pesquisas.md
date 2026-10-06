# Registo das pesquisas (RSL)

## String principal (versão 2)

```
("internet of things" OR "IoT")
AND ("intrusion detection" OR "anomaly detection" OR "malware detection" OR "botnet detection")
AND ("machine learning" OR "deep learning")
AND ("mitigation" OR "quarantine" OR "automated response" OR "intrusion prevention" OR "countermeasure")
```

A versão 1 (com "network traffic", "traffic analysis", "isolation", etc.) devolvia resultados a mais
(3184 no ACM e 1910 no IEEE, pesquisando em todos os campos) e foi abandonada.

## Pesquisa de 06/10/2026

Filtros comuns: pesquisa **só no resumo (abstract)**, anos **2020–2026**.

| Base | Campo | Filtros adicionais | Resultados |
| --- | --- | --- | ---: |
| IEEE Xplore | Abstract | — (All results) | 139 |
| ACM Digital Library | Abstract | Coleção *ACM Guide to Computing Literature* | 34 |
| Scopus | Abstract | Tipo de documento: *Article*, *Conference paper* | 342 |
| ScienceDirect | Abstract | String reduzida (ver abaixo) | 148 |
| MDPI | Abstract | — | 14 |
| **Total** | | | **677** |

String usada no ScienceDirect (limite de operadores booleanos por campo):

```
"IoT" AND ("intrusion detection" OR "anomaly detection" OR "botnet detection")
AND ("machine learning" OR "deep learning")
AND ("mitigation" OR "intrusion prevention" OR "automated response")
```

## Exportações

Ficheiros BibTeX (com resumo) em `exports/`, um por base: `ieee.bib`, `acm.bib`, `scopus.bib`,
`sciencedirect.bib`, `mdpi.bib`. Importados no Parsifal, cada um associado à sua base.

## Problemas nas exportações (06/10)

- **ScienceDirect:** o ficheiro só tem **25 dos 148** resultados (só a primeira página foi exportada). Falta exportar o resto.
- **ACM:** 10 dos 34 registos vieram **sem resumo**.

## Pré-triagem (06/10)

Ficheiro `pretriagem.csv`: registos únicos depois de juntar as cinco bases e remover duplicados (por DOI e por título),
com uma sugestão de decisão baseada no título. **A decisão final é do grupo**, na coluna "Decisão final".

| Sugestão | Registos |
| --- | ---: |
| Rever resumo (72 com prioridade alta para a QF3) | 283 |
| Dúvida | 1 |
| Revisão/survey (não é estudo primário, útil para contexto) | 45 |
| Excluir pelo título (critério indicado) | 65 |
| **Total de registos únicos** | **394** |

## Funil de seleção (preencher)

| Etapa | Artigos |
| --- | ---: |
| Resultados exportados | 554 (falta o resto do ScienceDirect) |
| Após remover duplicados (EC5) | 394 |
| Após título/resumo (EC1–EC4) | |
| Após three-pass (EC1–EC4) | |
| Incluídos | |
