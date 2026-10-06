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

Revisões lidas: Kandah et al. (2025), Bhardwaj et al. (2025), Vera-Mundaca et al. (2024) e Negera et al. (2022,
da pesquisa principal).

Decisões (06/10/2026):
- **String principal mantém-se.** As 8 revisões únicas da pesquisa secundária já constavam dos resultados da principal,
  e os termos que usam (mitigation, countermeasures, prevention) já estão cobertos.
- **Perguntas refinadas:** QF2 passa a incluir tipos de ataque; QF3 passa a incluir onde a resposta é aplicada
  (incluindo controlador SDN) e como é desencadeada; nova QF4 sobre o tipo de avaliação (offline vs tempo real/protótipo)
  e custo computacional.

## Perguntas de pesquisa (versão final)

- **QG** — Como é que a análise de tráfego com ML é usada para detetar e conter automaticamente dispositivos IoT comprometidos?
- **QF1** — Que modelos (supervisionados, não supervisionados, semi-supervisionados) e que features de tráfego são usados?
- **QF2** — Que datasets, tipos de ataque e métricas de avaliação são usados?
- **QF3** — Que mecanismos de resposta automática são propostos, onde são aplicados (dispositivo, gateway/edge, controlador SDN ou cloud) e como são desencadeados?
- **QF4** — As soluções são avaliadas apenas offline, com datasets, ou também em tempo real ou num protótipo, e com que custo computacional?
- **QE** — Quantas publicações existem por ano, por tipo de modelo e por dataset?

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
