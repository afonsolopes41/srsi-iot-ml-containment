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

## Pesquisa secundária (06/10/2026) — revisões sistemáticas

String principal + `AND ("systematic literature" OR "systematic review" OR "literature review")`, com os mesmos
filtros (resumo, 2020–2026). Serve só para encontrar revisões já publicadas e validar a string; estes artigos
**não** entram na triagem.

| Base | Resultados |
| --- | ---: |
| IEEE Xplore | 2 |
| ACM Digital Library | 0 |
| Scopus | 8 |
| ScienceDirect | 0 (a confirmar) |
| MDPI | 0 |
| **Total** | **10** |

Revisões lidas e decisões sobre a string: (preencher)

## Exportações

Ficheiros BibTeX exportados de cada base (com resumo), **sem alterações**, em `exports/`, com os nomes originais.
Cada base é importada no Parsifal associada ao(s) seu(s) ficheiro(s).

- **IEEE Xplore:** exporta no máximo 100 registos de cada vez, por isso tem dois ficheiros (139 registos).
- **ScienceDirect:** exporta uma página de cada vez, por isso tem seis ficheiros. Juntos têm 143 dos 148 resultados (a base não exportou 5 registos).
- **ACM:** 10 dos 34 registos vieram sem resumo; decidem-se pelo título ou abrindo o artigo.
- Exportações da pesquisa secundária em `exports/secundaria/` (não entram na triagem).

## Funil de seleção (preencher)

| Etapa | Artigos |
| --- | ---: |
| Resultados exportados | 554 (falta o resto do ScienceDirect) |
| Após remover duplicados (EC5) | 394 |
| Após título/resumo (EC1–EC4) | |
| Após three-pass (EC1–EC4) | |
| Incluídos | |
