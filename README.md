# system_login

Backend de cadastro e autenticação de usuários em **Go 1.27** com **MySQL** via Docker, seguindo Clean Code, SOLID e arquitetura em camadas.

## Pré-requisitos

- Go 1.27+
- Docker e Docker Compose
- Git e VS Code

## Configuração Inicial

1. Clone o repositório e entre na pasta `system_login`.
2. Copie `.env.example` para `.env` e ajuste as credenciais.
3. Suba o banco de dados:
   ```bash
   docker compose up -d mysql
   ```
4. Aplique as migrations:
   ```bash
   docker compose run --rm migrate
   ```
5. Rode a API:
   ```bash
   go run ./cmd/api
   ```

A API escuta em `APP_PORT` (padrão `8080`) e libera CORS para `CORS_ALLOWED_ORIGIN` (padrão `http://localhost:3000`).
