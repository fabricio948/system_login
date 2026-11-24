# Arquitetura do Sistema (`system_login`)

## Visão Geral

API backend em Go 1.27 estruturada em camadas com dependências apontando para abstrações (`interface`s), pronta para consumo por frontend React e evolução futura com mensageria.

## Camadas

- **Transport (`handler` / `controller`)**: decodifica requests JSON, valida formato de entrada, chama o `service` e escreve respostas HTTP padronizadas.
- **Business (`service`)**: implementa todas as regras de negócio (RN-01 a RN-43), controle de tentativas, bloqueios, sessões e recuperação de senha.
- **Persistence (`repository`)**: executa consultas SQL explícitas no MySQL e converte linhas em modelos Go.
- **Cross-cutting (`middleware`)**: autenticação, validação de status do usuário, CORS e tratamento de erros/pânico.

## Injeção de Dependência e Futuro

- Dependências são injetadas via construtores (`NewAuthService(repo, notifier, ...)`).
- Interfaces de notificação/eventos isolam o `service` de brokers futuros (RabbitMQ/Kafka).
