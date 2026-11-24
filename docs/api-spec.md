# Especificação da API (Base)

## Padrão de Resposta

- Formato: `application/json`.
- Códigos HTTP utilizados:
  - `200` OK
  - `201` Created
  - `400` Bad Request (formato inválido, código de recuperação inválido/expirado/usado)
  - `401` Unauthorized (credenciais inválidas, sem token, token expirado, conta desativada no login)
  - `404` Not Found (recurso inexistente ou pertencente a outro usuário)
  - `409` Conflict (e-mail já cadastrado)
  - `423` Locked (conta bloqueada temporária ou administrativamente)
  - `429` Too Many Requests (excesso de tentativas no código de recuperação)

## Grupos de Rotas Planejados

- Públicos: cadastro, login, refresh token, solicitar código de recuperação, redefinir senha.
- Autenticados (usuário ativo e não bloqueado): perfil, alterar nome, trocar senha, logout, desativar conta.
