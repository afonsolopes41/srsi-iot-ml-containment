# Deteção e contenção automática de dispositivos IoT comprometidos com Machine Learning

Projeto de grupo da unidade curricular **Segurança em Redes e Sistemas de Informação (SRSI)**, Mestrado em Engenharia de Telecomunicações e Informática, Iscte – Instituto Universitário de Lisboa, 2026/2027.

Docentes: Prof. Valderi Reis Quietinho Leithardt e Prof. Maurício Machado da Rosa

| Nome | N.º |
|---|---|
| Afonso Duarte Rosado Lopes | 122631 |
| Rafael Fernandes dos Reis | 122616 |
| Rafael Andrade da Silva | 122638 |
| Gonçalo José Bilé Batista | 122623 |
| João Azinheira Alves | 123488 |

## Sobre o projeto

O projeto tem duas partes:

- **Parte 1 – Revisão sistemática da literatura (RSL).** Como é que a análise de tráfego com *machine learning* é usada para detetar e conter automaticamente dispositivos IoT comprometidos. A revisão partiu de 677 resultados em cinco bases de dados e incluiu 31 estudos. Termina com a proposta da arquitetura a implementar na Parte 2 e com o seu enquadramento numa arquitetura *Zero Trust* (NIST SP 800-207).
- **Parte 2 – Protótipo.** Um *gateway* em contentores Docker que extrai fluxos com o Zeek, compara *Random Forest*, *Isolation Forest* e *autoencoder* sobre o IoT-23 e coloca automaticamente em quarentena, com nftables, os dispositivos suspeitos. *(Ainda não realizada.)*

## Estrutura do repositório

```
report/                                         Relatório da Parte 1 (LaTeX, formato IEEE)
  main.tex                                      Código-fonte do relatório
  referencias.bib                               Referências (BibTeX)
  figuras/                                      Imagens usadas no relatório
  SRSI-122631_122616_122638_122623_123488.pdf   Relatório em PDF
rsl/                                            Dados da revisão sistemática
  protocolo_parsifal.docx                       Protocolo exportado do Parsifal: PICOC, perguntas, string, bases, critérios e avaliação de qualidade
  pesquisas.md                                  Registo das pesquisas: datas, filtros, resultados por base e decisões
  exports/                                      Exportações BibTeX de cada base (string principal)
  exports/secundaria/                           Exportações da string secundária (revisões já publicadas)
  extracao/data_extraction.xls                  Formulário de extração exportado do Parsifal (31 estudos)
  artigos/                                      PDF dos estudos incluídos
```

## Processo da revisão (resumo)

| Etapa | Estudos |
|---|---|
| Resultados nas cinco bases | 677 |
| Importados no Parsifal | 660 |
| Estudos únicos (após 169 duplicados) | 491 |
| Aceites na seleção: título, resumo e EC6 (421 excluídos) | 70 |
| Com avaliação de qualidade Q(e) ≥ 5 (33 excluídos) | 37 |
| Incluídos após a revisão final (6 excluídos pelo EC6) | **31** |

A triagem, a avaliação de qualidade e a extração foram feitas na ferramenta [Parsifal](https://parsif.al). Os PDF dos estudos incluídos estão em `rsl/artigos/`.
