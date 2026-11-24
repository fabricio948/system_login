# Banco de Dados e Administração (MySQL)

## Execução via Docker

- Subir banco: `docker compose up -d`
- Acessar MySQL no container: `docker exec -it system_login_mysql mysql -u root -p`

## Migrations

- Scripts SQL ficam em `migrations/`.
- Na primeira inicialização do volume, o MySQL executa os arquivos em `/docker-entrypoint-initdb.d`. Para ambientes já iniciados ou controle explícito, aplicar os scripts `.up.sql` via CLI MySQL ou ferramenta de migration dedicada.

## Restrição do Administrador

- O administrador atua diretamente no banco para consultar usuários, bloquear e reativar.
- Não deve alterar `password_hash` nem `email`.
- Recomendação operacional: criar usuário MySQL administrativo com `SELECT` em `users` e `UPDATE` restrito às colunas de bloqueio e contador de falhas (`is_admin_blocked`, `blocked_until`, `block_type`, `block_reason`, `blocked_at`, `failed_login_attempts`).
