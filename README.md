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
   docker compose up -d
   ```
