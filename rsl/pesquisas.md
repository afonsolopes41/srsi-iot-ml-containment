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
| ScienceDirect | 0 |
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

## Protocolo

As perguntas de pesquisa finais, o PICOC, os critérios de inclusão e exclusão e as perguntas da avaliação de
qualidade estão no protocolo exportado do Parsifal (`protocolo_parsifal.docx`).

## Exportações

Ficheiros BibTeX exportados de cada base (com resumo), **sem alterações**, em `exports/`, com os nomes originais.
Cada base é importada no Parsifal associada ao(s) seu(s) ficheiro(s).

- **IEEE Xplore:** exporta no máximo 100 registos de cada vez, por isso tem dois ficheiros (139 registos).
- **ScienceDirect:** exporta uma página de cada vez, por isso tem seis ficheiros. Juntos têm 143 dos 148 resultados (a base não exportou 5 registos).
- **ACM:** 10 dos 34 registos vieram sem resumo; decidem-se pelo título ou abrindo o artigo.
- Exportações da pesquisa secundária em `exports/secundaria/` (não entram na triagem).

## Funil de seleção

| Etapa | Artigos |
| --- | ---: |
| Resultados nas bases | 677 |
| Importados no Parsifal ("All") | 660 |
| Duplicados (EC5) | 169 |
| Estudos únicos | 491 |
| Excluídos no título/resumo (EC1–EC4) e pelo EC6 | 421 |
| Chegam à avaliação de qualidade | 70 |
| Excluídos por Q(e) < 5 | 33 |
| Excluídos na revisão final (EC6) | 6 |
| **Incluídos** | **31** |

## Critério EC6 (refinamento)

Acrescentado depois da primeira leitura dos resumos: **EC6, o estudo não propõe nem avalia um mecanismo de resposta ou contenção automática.** Muitos estudos só tratavam a deteção e referiam a mitigação de passagem, sem responderem à questão geral (detetar **e** conter).

Na revisão final do conjunto, seis estudos que tinham passado a avaliação de qualidade foram excluídos pelo EC6, por
não proporem qualquer mecanismo de resposta (limitavam-se à classificação, a um alerta ou a uma notificação ao
utilizador). No Parsifal estão marcados como rejeitados pelo EC6, por isso a ferramenta mostra 64 aceites e 427
rejeitados.
