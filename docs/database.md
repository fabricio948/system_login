# Banco de Dados e Administração (MySQL)

## Execução via Docker

- Subir banco: `docker compose up -d mysql`
- Acessar MySQL no container: `docker exec -it system_login_mysql mysql -u root -p`

## Migrations

- Scripts SQL ficam em `migrations/` no formato `{versão}_{nome}.up.sql` e `{versão}_{nome}.down.sql`.
- O diretório **não** é montado em `/docker-entrypoint-initdb.d`: esse entrypoint executa também os `.down.sql` e só roda em volume vazio, impedindo que migrations novas fossem aplicadas.
- As migrations são aplicadas pelo [golang-migrate](https://github.com/golang-migrate/migrate) através do serviço `migrate` (profile `tools`):

  ```bash
  docker compose up -d mysql
  docker compose run --rm migrate          # aplica todas as migrations pendentes
  docker compose run --rm migrate version  # mostra a versão atual
  docker compose run --rm migrate down 1   # desfaz a última migration
  docker compose run --rm migrate force 3  # marca a versão 3 como aplicada (reparo)
  ```

- O controle de versão fica na tabela `schema_migrations`, criada automaticamente.
- A DSN usa `MYSQL_USER`, `MYSQL_PASSWORD` e `MYSQL_DATABASE` do `.env`. Se a senha contiver caracteres especiais (`@`, `:`, `/`), ela deve ser URL-encoded.
- Nunca edite uma migration já aplicada; crie uma nova versão.

## Restrição do Administrador

- O administrador atua diretamente no banco para consultar usuários, bloquear e reativar.
- Não deve alterar `password_hash` nem `email`.
- Recomendação operacional: criar usuário MySQL administrativo com `SELECT` em `users` e `UPDATE` restrito às colunas de bloqueio e contador de falhas (`is_admin_blocked`, `blocked_until`, `block_type`, `block_reason`, `blocked_at`, `failed_login_attempts`).
