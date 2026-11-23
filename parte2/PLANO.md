# Parte 2 – Plano de trabalho

Objetivo: implementar e avaliar **exatamente** o que a Parte 1 prometeu (relatório, Secção
"Solução proposta" e "Enquadramento na arquitetura Zero Trust"). Os contratos entre as partes
estão em [`docs/interfaces.md`](docs/interfaces.md). **Entrega: segunda-feira, 7/12/2026, às 23:59** (um único `GROUP_[N].zip`, submetido por
uma só pessoa, mais o vídeo de apresentação, com no máximo 15 min e a participação de todos).

## Critérios de avaliação (20 valores)

| Critério | Valores | O que conta para nós |
|---|---|---|
| Implementação | 8 | Protótipo completo a correr com um comando: Zeek → deteção → decisão → nftables, com os 3 modelos e os registos parciais |
| Testes e comparativos práticos | 6 | RF vs IF vs AE à mesma FPR, contra o baseline do Zeek; S1/S2/S3; T_c, quarentenas indevidas, CPU e memória; controlo sem porta |
| Validação do protótipo | 4 | Mostrar que cada promessa se cumpre: replay fiel, ordem das regras, corte de ligações estabelecidas, expiração e renovação, casos de uso ZTA |
| Relatório e vídeo | 2 | Relatório curto em LaTeX (mesmo formato da Parte 1) e vídeo de demonstração |

## Calendário

### Semana 1 (23–29/11): tudo implementado

| Quem | Tarefas | Entrega (pastas) |
|---|---|---|
| **Afonso Lopes** (coordenação) | Banco de ensaio Docker (gateway, sub-redes, Zeek, nftables); escolha das capturas do IoT-23, conversão para Parquet e `splits.json` (divisão por captura); replay com `tcprewrite`/`tcpreplay` à velocidade original e verificação contra o IoT-23; deteção em tempo real; script dos cenários (T_c, CPU, memória); integração | `gateway/`, `node/`, `training/prepare_dataset.py`, `data/splits.json`, `src/srsi/detector.py`, `experiments/` |
| **Rafael Silva** | `FeaturePipeline` (o mais cedo possível: os modelos dependem dela); Random Forest; ensaio de controlo sem porta | `src/srsi/features.py`, `training/train_rf.py`, `models/rf*/` |
| **Rafael Reis** | Isolation Forest; autoencoder (só benigno, θ = p99); script de avaliação offline comum aos 3 modelos (mesma FPR; P/R/F1/FPR/PAM; ROC) | `training/train_iforest.py`, `training/train_autoencoder.py`, `src/srsi/metrics.py`, `training/evaluate_offline.py` |
| **Gonçalo Batista** | Decisão k-de-w por dispositivo; contenção no nftables (adicionar, renovar, libertar, registar hora e motivo); baseline sem ML com o detetor de varrimentos do Zeek | `src/srsi/decision.py`, `src/srsi/containment.py`, `gateway/zeek/` (baseline) |
| **João Alves** | Capturas de ecrã no Wireshark do tráfego de ataque das capturas escolhidas (Mirai, Torii), para o relatório e o vídeo | `results/figuras/wireshark/` |

### Semana 2 (30/11–6/12): resultados, relatório e vídeo

| Quem | Tarefas |
|---|---|
| **Afonso Lopes** | Correr as experiências S1/S2/S3 × {RF, IF, AE, baseline} (3 repetições); **relatório**; guião do vídeo; montagem do vídeo e submissão |
| **Rafael Silva** | Análise da diferença entre registos parciais e completos |
| **Rafael Reis** | Métricas e gráficos offline; análise estatística das experiências |
| **Gonçalo Batista** | Escolha de k e w (T_c vs quarentenas indevidas); testes de aceitação dos 4 casos de uso ZTA |
| **João Alves** | README "como correr"; preparar o `GROUP_[N].zip` (o Afonso confere antes de submeter) |
| **Todos** | A meio da semana, enviar ao Afonso os resultados (tabelas, gráficos) e um resumo do que fizeram e das decisões tomadas. **Domingo 6/12: gravação do vídeo** (~3 min cada) |

Segunda 7/12 fica só para submeter.

### Ligação aos critérios de avaliação

| Trabalho | Critério |
|---|---|
| Banco de ensaio, deteção em tempo real, decisão, contenção, 3 modelos | Implementação (8) |
| Avaliação offline à mesma FPR, ensaio sem porta, experiências S1/S2/S3, baseline do Zeek, T_c/CPU/memória | Testes e comparativos (6) |
| Verificação do replay, ordem das regras, corte de ligações estabelecidas, expiração/renovação, casos de uso ZTA, registos parciais | Validação do protótipo (4) |
| Relatório e vídeo | Relatório e vídeo (2) |

### Dependências

```
dados + splits (Afonso) ─> features (R. Silva) ─┬─> RF (R. Silva) ───────┐
                                                └─> IF / AE (R. Reis) ───┤
replay (Afonso) ─────────────────────────────────────────────────────────┤
decisão / contenção (Gonçalo, usa o modelo provisório) ──────────────────┼─> experiências ─> relatório ─> vídeo
deteção em tempo real (Afonso, usa o modelo provisório) ─────────────────┘
```

## Decisões a fechar em grupo (propostas)

| Decisão | Proposta | Porquê |
|---|---|---|
| FPR alvo comum | 1 % (benigno de validação) | Coincide com o θ = p99 prometido para o AE |
| Grelha de k e w | w ∈ {5, 10, 20}, k ∈ {1, 2, 3, 5} com k ≤ w | Inclui os pontos da literatura (3 fluxos; 5 seguidos) |
| Expiração da quarentena | 300 s nas experiências, 20 s nos testes | Cabe numa experiência e permite ver a renovação |
| Intervalo dos registos parciais | 30 s | Compromisso entre T_c em C&C e volume de registos |
| Repetições por cenário | 3 | Média e desvio padrão de T_c dentro do prazo |
| Máquina das medições de tempo e CPU | uma só (a do Afonso), com as especificações no relatório | Os valores medidos em máquinas diferentes não são comparáveis |

## Forma de trabalhar

* Um ramo por tarefa (`p2/<nome>-<tema>`, ex. `p2/goncalo-contencao`) e Pull Request para a
  `main`. O Afonso revê e integra. Cada um faz commits com o seu nome.
* Antes de abrir um PR: `pytest` sem falhas. Se mexer na rede ou no gateway, também `scripts/smoke_test.sh`.
* Dados grandes (IoT-23, pcaps, logs) **não** vão para o Git (`.gitignore`); ficam na pasta
  partilhada do grupo, e o Git guarda os scripts que os geram.
* Mudanças a um contrato: atualizar `docs/interfaces.md` no mesmo PR e avisar quem o consome.

## Riscos

| Risco | Mitigação |
|---|---|
| Docker Desktop (Windows/macOS) sem módulos de kernel para o espelho `tc` | O gateway recorre a um par veth se o kernel não tiver `dummy`; testar a F0 em todas as máquinas até 25/11; em último caso, WSL2 com Docker Engine nativo |
| O replay não reproduz os `conn.log` do IoT-23 | Comparação sistemática na F1 (validação); usar `--enet-dmac` com o MAC do gateway e velocidade original |
| Pouco benigno (3 dispositivos) → FPR alta no S1 com IF e AE | Já assumido na Parte 1; reportar e discutir em vez de esconder |
| A porta 23 domina o RF | Porta agrupada e ensaio de controlo sem porta (prometido) |
| Capturas enormes (dezenas de milhões de fluxos) | Leitura por blocos (`iter_iot23_labeled`) e amostragem estratificada por captura, documentada |
