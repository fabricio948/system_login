# Regras de Negócio Consolidadas

Resumo das diretrizes principais extraídas da Regra de Negócio (v3) e alinhamentos do projeto:

- **Cadastro**: nome (> 3 caracteres), e-mail único case-insensitive, exceto `.org` e `.edu.br`; senha (>= 8 caracteres, letra, número e especial) salva apenas como hash; e-mail de conta desativada permanece reservado.
- **Login e Bloqueio**: 4 falhas consecutivas bloqueiam por 10 minutos (`423`); bloqueio administrativo sem prazo via banco; contador de falhas zera no sucesso, no fim do bloqueio temporário ou na reativação pelo admin.
- **Sessão**: access token (15 min) e refresh token (7 dias) com rotação no refresh, revogação no logout, encerramento de todas as sessões ao trocar/redefinir senha, suporte a múltiplos dispositivos e checagem contínua de status ativo/não bloqueado (`423`).
- **Recuperação de Senha**: código numérico de 6 dígitos (15 min, uso único, invalida após 5 erros com `429`, novo código invalida anterior, e-mail inexistente retorna código falso não utilizável; devolução na resposta apenas enquanto não há mensageria).
