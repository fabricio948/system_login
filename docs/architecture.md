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

## Tokens e Hashing

- Access e refresh tokens são valores opacos aleatórios (não JWT); o banco guarda apenas o SHA-256 em hexadecimal, compatível com as colunas `CHAR(64)`.
- O código de recuperação tem baixa entropia (6 dígitos) e é validado por HMAC-SHA256 usando `RECOVERY_CODE_PEPPER` do `.env`, também armazenado como 64 caracteres hexadecimais.
- Senhas usam bcrypt e nunca são persistidas em texto puro.

## Mensageria e Notificações

- `NotificationService` e `EventPublisher` isolam o `service` de provedores externos.
- As implementações atuais (`LogNotificationService` e `LogEventPublisher`) apenas registram o evento em log; o código de recuperação é devolvido na resposta enquanto a entrega real não existe.
- Eventos publicados: cadastro, login, falha de login, bloqueio, refresh, logout, troca/redefinição de senha, exclusão de conta e solicitação de recuperação.
