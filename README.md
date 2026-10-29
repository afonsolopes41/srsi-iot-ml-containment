# Deteção e contenção automática de dispositivos IoT comprometidos com Machine Learning

Projeto de grupo da unidade curricular **Segurança em Redes e Sistemas de Informação (SRSI)**, Mestrado em Engenharia de Telecomunicações e Informática, Iscte – Instituto Universitário de Lisboa, 2026/2027.

Docente: Prof. Valderi Reis Quietinho Leithardt

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
- **Parte 2 – Protótipo.** Um *gateway* em contentores Docker que extrai fluxos com o Zeek, compara *Random Forest*, *Isolation Forest* e *autoencoder* sobre o IoT-23 e coloca automaticamente em quarentena, com nftables, os dispositivos suspeitos. *(Segunda parte do Projeto, ainda não realizado.)*

## Estrutura do repositório

```
relatorio/                         Relatório da Parte 1 (LaTeX, formato IEEE)
  main.tex                         Código-fonte do relatório
  referencias.bib                  Referências (BibTeX)
  figuras/                         Imagens usadas no relatório
  SRSI_Relatorio_Parte1.pdf        Versão compilada
rsl/                               Dados da revisão sistemática
  protocolo.md                     Perguntas, string de busca, bases, critérios e avaliação de qualidade
  pesquisa/principal/              Exportações BibTeX de cada base (string principal)
  pesquisa/secundaria/             Exportações da string secundária (revisões já publicadas)
  selecao/estudos_incluidos.csv    Os 31 estudos incluídos, com a pontuação de qualidade
  selecao/                         Folhas de triagem
  extracao/                        Formulários de extração exportados do Parsifal
```

## Processo da revisão (resumo)

| Etapa | Estudos |
|---|---|
| Resultados nas cinco bases | 677 |
| Importados no Parsifal | 660 |
| Estudos únicos (após 169 duplicados) | 491 |
| Aceites na seleção: título, resumo e EC6 (427 excluídos) | 64 |
| Incluídos após avaliação de qualidade, Q(e) ≥ 5 (33 excluídos) | **31** |

A triagem, a avaliação de qualidade e a extração foram feitas na ferramenta [Parsifal](https://parsif.al). Os PDF dos artigos não estão no repositório por questões de direitos de autor; cada estudo pode ser obtido pelo DOI indicado em `rsl/selecao/estudos_incluidos.csv`.

