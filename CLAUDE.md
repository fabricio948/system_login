# CLAUDE.md — Diretrizes de Desenvolvimento (system_login)

## Idioma e Convenções

- Código, nomes de arquivos, pastas, pacotes, structs, interfaces, funções, variáveis e comentários no Git/código: **Inglês**.
- Documentação (`README.md`, `CLAUDE.md`, `docs/`) e explicações ao usuário: **Português**.
- Comentários no código devem ser curtos, objetivos e explicar apenas regras não óbvias.
- Commits seguem Conventional Commits, com foco em `feat:` e `fix:` (além de `docs:`, `chore:`, `test:`).

## Stack e Arquitetura

- Go 1.27, biblioteca padrão (`net/http`, `database/sql`, `context`, etc.) e SQL puro (sem ORM).
- Arquitetura em camadas com injeção de dependência via `struct` e `interface`:
  `cmd/api` -> `handler` / `controller` -> `service` -> `repository` -> MySQL.
- Middlewares idiomáticos com `func(http.Handler) http.Handler`.
- Desacoplamento futuro: definir interfaces como `NotificationService` / `EventPublisher` para mensageria futura sem alterar regras de negócio.

## Rotina Obrigatória em Toda Análise ou Alteração

1. Ler `CLAUDE.md`, `docs/*`, `docker-compose.yml`, `.env` e `.gitignore`.
2. Validar o código com `gofmt -l .`, `go vet ./...` e `go test ./...`.
3. Subir ou verificar o container MySQL (`docker compose up -d`) quando testar integração/banco.
4. Testar os endpoints HTTP quando alterar rotas ou fluxos da API.
5. Verificar se há pendências de commit ou organização antes de concluir.
