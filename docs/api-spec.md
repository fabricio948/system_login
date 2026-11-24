# Especificação da API (`system_login`)

## Padrão Geral

- Content-Type: `application/json`.
- Autenticação em rotas protegidas: `Authorization: Bearer <access_token>`.
- Códigos HTTP: `200`, `201`, `400`, `401`, `404`, `409`, `423`, `429`.
- Senha nunca é retornada em nenhuma resposta (`RN-07`).

## Rotas Públicas

- `POST /auth/register`: cria usuário (`201`). Valida nome (> 3 chars), e-mail único case-insensitive sem `.org`/`.edu.br`, senha forte. E-mail já cadastrado ou reservado de conta desativada retorna conflito/recusa (`409` ou `400` conforme padronização do handler).
- `POST /auth/login`: autentica e devolve `access_token` e `refresh_token` (`200`).
  - Credenciais inválidas ou conta desativada: `401` ("credenciais inválidas").
  - 4ª falha consecutiva ou conta já bloqueada: `423` com motivo/mensagem de bloqueio e tempo restante (quando bloqueio temporário).
- `POST /auth/refresh`: recebe `refresh_token`, rotaciona o token (`RN-22`), valida status ativo/não bloqueado do usuário (`RN-25`) e retorna novo par de tokens (`200`), `401` se inválido/expirado ou `423` se bloqueado.
- `POST /auth/password/forgot`: recebe `email`. Sempre responde `200` com mensagem padrão e código de 6 dígitos (`RN-35`, `RN-42`, `RN-43`). Se o e-mail não existir, devolve código falso não utilizável.
- `POST /auth/password/reset`: recebe `email`, `code` e `new_password`. Valida código (15 min, uso único, até 5 tentativas) e nova senha, atualiza hash, encerra sessões abertas (`RN-24`, `RN-40`) e não remove bloqueios (`RN-41`). Excesso de tentativas retorna `429`.

## Rotas Autenticadas (Usuário Ativo e Não Bloqueado)

- `GET /users/me`: retorna dados do próprio perfil (`200`).
- `PATCH /users/me/name`: altera o próprio nome (`200`).
- `POST /users/me/change-password`: exige `current_password` e `new_password` (diferente da atual), atualiza hash e encerra sessões abertas (`200` / `400` / `401`).
- `POST /auth/logout`: revoga o token/sessão atual (`200`).
- `DELETE /users/me`: soft delete da conta (`is_active = false`), encerra sessões e mantém e-mail reservado (`200`).

## Regra de Isolamento de Recurso

- Tentativas de acessar ou alterar dados de outro usuário retornam `404` (`RN-29`).
