# system_login

Backend de cadastro e autenticação de usuários em **Go 1.27** com **MySQL 8.4** via Docker. O projeto usa `net/http`, `database/sql`, SQL puro (sem ORM) e arquitetura em camadas com injeção de dependência por construtor.

## Funcionalidades

- Cadastro com nome, e-mail único case-insensitive (bloqueando `.org` e `.edu.br`) e senha forte armazenada apenas como hash bcrypt.
- Login com bloqueio temporário após 4 falhas consecutivas (10 minutos, HTTP `423`) e suporte a bloqueio administrativo sem prazo.
- Access token de 15 minutos, refresh token de 7 dias, rotação no refresh, logout e múltiplos dispositivos.
- Encerramento de todas as sessões ao trocar/redefinir senha ou desativar a conta.
- Recuperação de senha com código numérico de 6 dígitos, HMAC com pepper, validade de 15 minutos, uso único e limite de 5 tentativas.
- Perfil do usuário, alteração de nome, troca de senha e soft delete mantendo o e-mail reservado.
- Middleware de autenticação com checagem contínua de conta ativa/não bloqueada, CORS para o frontend React e recuperação de panic com resposta JSON.

## Stack e arquitetura

- **Go 1.27** com biblioteca padrão.
- **MySQL 8.4** em container Docker.
- **SQL puro** com `database/sql` e `github.com/go-sql-driver/mysql`.
- **bcrypt** para senhas e **HMAC-SHA256** para códigos de recuperação.
- Camadas: `cmd/api` → `handler` / `middleware` → `service` → `repository` → MySQL.
- Interfaces de notificação (`NotificationService`) e eventos (`EventPublisher`) desacopladas para mensageria futura.

### Estrutura de pastas

```text
.
├── cmd/api/              # entrada da API, wiring e graceful shutdown
├── internal/
│   ├── config/           # carregamento e validação do .env / variáveis de ambiente
│   ├── handler/          # handlers HTTP e respostas JSON
│   ├── httpx/            # decodificação, respostas e mapeamento de erros
│   ├── middleware/       # autenticação, CORS e recuperação de panic
│   ├── model/            # modelos de domínio e erros sentinela
│   ├── repository/       # SQL puro e interfaces de persistência
│   └── service/          # regras de negócio
├── migrations/           # migrations up/down
├── docs/                 # arquitetura, banco, regras de negócio e API
├── docker-compose.yml
├── Dockerfile
└── .env.example
```

## Pré-requisitos

- Go 1.27+
- Docker e Docker Compose
- Git

## Configuração

1. Clone o repositório e entre na pasta:

   ```bash
   git clone https://github.com/fabricio948/system_login.git
   cd system_login
   ```

2. Crie o `.env` a partir do exemplo:

   ```bash
   cp .env.example .env
   ```

3. Ajuste as credenciais e gere um pepper forte para os códigos de recuperação:

   ```bash
   openssl rand -hex 32
   # copie o valor para RECOVERY_CODE_PEPPER no .env
   ```

O `.env` é ignorado pelo Git. Nunca versione credenciais reais.

### Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `APP_ENV` | `development` | Ambiente da aplicação |
| `APP_PORT` | `8080` | Porta HTTP da API |
| `ACCESS_TOKEN_TTL` | `15m` | Validade do access token |
| `REFRESH_TOKEN_TTL` | `168h` | Validade do refresh token (7 dias) |
| `RECOVERY_CODE_TTL` | `15m` | Validade do código de recuperação |
| `MAX_FAILED_LOGIN_ATTEMPTS` | `4` | Falhas antes do bloqueio temporário |
| `TEMP_BLOCK_DURATION` | `10m` | Duração do bloqueio temporário |
| `MAX_RECOVERY_ATTEMPTS` | `5` | Erros que invalidam o código de recuperação |
| `RECOVERY_CODE_PEPPER` | — | Segredo HMAC do código (mínimo 32 caracteres) |
| `CORS_ALLOWED_ORIGIN` | `http://localhost:3000` | Origem permitida no CORS |
| `MYSQL_HOST` | `localhost` | Host do MySQL |
| `MYSQL_PORT` | `3306` | Porta do MySQL |
| `MYSQL_DATABASE` | `system_login` | Banco da aplicação |
| `MYSQL_USER` | `app_user` | Usuário da aplicação |
| `MYSQL_PASSWORD` | — | Senha do usuário da aplicação |
| `MYSQL_ROOT_PASSWORD` | — | Senha root usada pelo container MySQL |

## Banco de dados

Suba o MySQL:

```bash
docker compose up -d mysql
```

Aplique as migrations com golang-migrate:

```bash
docker compose run --rm migrate          # aplica migrations pendentes
docker compose run --rm migrate version  # mostra a versão atual
docker compose run --rm migrate down 1   # desfaz a última migration
```

O controle fica na tabela `schema_migrations`. As migrations estão em `migrations/` no formato `{versão}_{nome}.up.sql` e `.down.sql`.

## Executar a API

A partir da raiz do projeto:

```bash
go run ./cmd/api
```

Ou gere um binário:

```bash
go build -o bin/api ./cmd/api
./bin/api
```

A API escuta em `http://localhost:${APP_PORT}`. O log inicia com `api started` e o encerramento é gracioso via `SIGINT`/`SIGTERM`.

Também é possível gerar a imagem Docker:

```bash
docker build -t system_login_api .
```

> O `docker-compose.yml` sobe apenas o MySQL; a API é executada localmente ou pela imagem construída.

## Endpoints

### Rotas públicas

| Método | Rota | Status de sucesso | Corpo |
|---|---|---|---|
| `POST` | `/auth/register` | `201` | `{"name","email","password"}` |
| `POST` | `/auth/login` | `200` | `{"email","password"}` |
| `POST` | `/auth/refresh` | `200` | `{"refresh_token"}` |
| `POST` | `/auth/password/forgot` | `200` | `{"email"}` |
| `POST` | `/auth/password/reset` | `200` | `{"email","code","new_password"}` |

### Rotas autenticadas

Envie `Authorization: Bearer <access_token>`.

| Método | Rota | Status de sucesso | Corpo |
|---|---|---|---|
| `POST` | `/auth/logout` | `200` | — |
| `GET` | `/users/me` | `200` | — |
| `PATCH` | `/users/me/name` | `200` | `{"name"}` |
| `POST` | `/users/me/change-password` | `200` | `{"current_password","new_password"}` |
| `DELETE` | `/users/me` | `200` | — |

### Códigos de erro

| Status | Situação |
|---|---|
| `400` | Validação, JSON inválido, código de recuperação inválido/expirado ou nova senha igual à atual |
| `401` | Credenciais inválidas, token inválido/expirado ou senha atual incorreta |
| `404` | Usuário ou rota não encontrados |
| `409` | E-mail já cadastrado ou reservado por conta desativada |
| `423` | Conta bloqueada temporariamente, bloqueada pelo admin ou inativa |
| `429` | Limite de tentativas de recuperação excedido |
| `500` | Erro interno ou panic recuperado |

Erros seguem o formato:

```json
{
  "error": {
    "code": "user_blocked",
    "message": "account temporarily blocked",
    "reason": "too many failed login attempts",
    "blocked_until": "2026-11-24T20:10:00Z",
    "remaining_seconds": 600
  }
}
```

## Exemplos com curl

Defina as variáveis:

```bash
BASE=http://localhost:8080
EMAIL="alice@example.com"
PASSWORD="Secret123!"
```

Cadastro:

```bash
curl -i -X POST "$BASE/auth/register" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"Alice\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
```

Login e captura dos tokens:

```bash
LOGIN=$(curl -s -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")

ACCESS=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' <<<"$LOGIN")
REFRESH=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["refresh_token"])' <<<"$LOGIN")
```

Perfil e alteração de nome:

```bash
curl -i "$BASE/users/me" -H "Authorization: Bearer $ACCESS"

curl -i -X PATCH "$BASE/users/me/name" \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Alice Silva"}'
```

Refresh com rotação:

```bash
curl -i -X POST "$BASE/auth/refresh" \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}"
```

Esqueci a senha e redefinição:

```bash
FORGOT=$(curl -s -X POST "$BASE/auth/password/forgot" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\"}")

CODE=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["code"])' <<<"$FORGOT")

curl -i -X POST "$BASE/auth/password/reset" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"code\":\"$CODE\",\"new_password\":\"NewSecret456!\"}"
```

O código é devolvido na resposta apenas enquanto não há provedor de mensageria. `LogNotificationService` reporta entrega desabilitada; ao plugar um provedor real, o código deixa de ser retornado.

Logout e desativação:

```bash
curl -i -X POST "$BASE/auth/logout" -H "Authorization: Bearer $ACCESS"

curl -i -X DELETE "$BASE/users/me" -H "Authorization: Bearer $ACCESS"
```

Após troca/redefinição de senha ou exclusão da conta, todas as sessões são revogadas.

## Testes

### Validações obrigatórias

```bash
gofmt -l .
go vet ./...
go test ./...
```

Cobertura:

```bash
go test -cover ./...
```

### Testes de integração do repository

Requer MySQL em execução e migrations aplicadas:

```bash
set -a; . ./.env; set +a

export TEST_MYSQL_DSN="${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(${MYSQL_HOST}:${MYSQL_PORT})/${MYSQL_DATABASE}?parseTime=true&loc=UTC&collation=utf8mb4_unicode_ci&clientFoundRows=true"

go test -tags=integration ./internal/repository -v
```

Os testes criam e removem os próprios usuários de teste.

### Teste manual rápido

Com a API rodando:

1. Cadastre um usuário com `POST /auth/register`.
2. Faça login e use o `access_token` em `GET /users/me`.
3. Faça refresh e confirme que o refresh token antigo retorna `401`.
4. Faça logout e confirme que o access token retorna `401`.
5. Solicite recuperação, redefina a senha e confirme que as sessões anteriores foram revogadas.
6. Erre a senha 4 vezes e confirme o bloqueio `423`.
7. Altere a senha, desative a conta e confirme que o e-mail continua reservado.

### Bloqueio administrativo

O administrador atua diretamente no banco:

```sql
UPDATE users
SET is_admin_blocked = TRUE,
    block_type = 'admin',
    block_reason = 'revisão de compliance'
WHERE email = 'alice@example.com';
```

Para reativar:

```sql
UPDATE users
SET is_admin_blocked = FALSE,
    block_type = NULL,
    block_reason = NULL,
    blocked_at = NULL,
    blocked_until = NULL,
    failed_login_attempts = 0
WHERE email = 'alice@example.com';
```

## Segurança

- Senhas usam bcrypt e nunca são retornadas em respostas.
- Access e refresh tokens são valores opacos aleatórios; o banco guarda somente SHA-256 em hexadecimal.
- O refresh token é rotacionado e a sessão antiga é revogada.
- O código de recuperação é armazenado como HMAC-SHA256 com `RECOVERY_CODE_PEPPER`.
- Login retorna `401` genérico para e-mail inexistente, senha incorreta ou conta inativa, com bcrypt dummy para reduzir enumeração por timing.
- Bloqueios temporários e administrativos retornam `423` com motivo e tempo restante quando aplicável.
- O e-mail de conta desativada permanece reservado pelo índice único.
- CORS libera a origem configurada em `CORS_ALLOWED_ORIGIN` (ou todas quando o valor é `*`).

## Documentação adicional

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/database.md`](docs/database.md)
- [`docs/business-rules.md`](docs/business-rules.md)
- [`docs/api-spec.md`](docs/api-spec.md)

## Próximos passos

- Implementar provedor real de notificação (e-mail/SMS) e publicar eventos em broker.
- Criar ferramentas administrativas para bloqueio/reativação.
- Agendar limpeza de sessões expiradas (`DeleteExpired` já disponível no repository).
- Adicionar CI e testes HTTP automatizados no repositório.
