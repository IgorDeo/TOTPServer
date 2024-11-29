# TOTPServer

## O que é TOTP?

TOTP (Time-based One-Time Password) é um algoritmo que gera senhas temporárias únicas baseadas em tempo. É uma extensão do algoritmo HOTP (HMAC-based One-Time Password) e é amplamente utilizado em autenticação de dois fatores (2FA).

## Como funciona?

O TOTP funciona através dos seguintes passos:

1. **Geração da Chave Secreta**
   - Uma chave secreta compartilhada é gerada entre o servidor e o cliente
   - Esta chave é geralmente codificada em Base32 para facilitar a digitação
   - No nosso projeto, isso é feito através do endpoint `/users/{user_id}/generate-secret`

2. **Cálculo do Contador de Tempo (T)**
   - T = (Tempo Unix Atual) ÷ (Intervalo)
   - O intervalo padrão é 30 segundos
   - Isso garante que o mesmo código seja gerado durante este intervalo

3. **Geração do HMAC**
   - Um HMAC-SHA1 é calculado usando a chave secreta e o contador T
   - O resultado é um hash de 20 bytes

4. **Truncamento Dinâmico**
   - O último byte do hash determina um offset
   - 4 bytes são extraídos a partir deste offset
   - O número é reduzido para obter N dígitos (geralmente 6)

## Implementação neste Projeto

Este projeto implementa uma API REST que oferece:

- Criação de usuários
- Geração de chaves secretas TOTP
- Validação de códigos TOTP
- Armazenamento seguro das chaves usando criptografia Fernet
- Proteção contra reutilização de códigos

### Endpoints Principais

- `POST /users/`: Cria um novo usuário
- `POST /users/{user_id}/generate-secret`: Gera uma chave secreta para o usuário
- `POST /validate-totp`: Valida um código TOTP fornecido

## Vulnerabilidades de Segurança

### Ataque de Força Bruta

A principal vulnerabilidade do TOTP é a possibilidade de ataques de força bruta. Como o código TOTP tem apenas 6 dígitos por padrão, existem apenas 1 milhão (10^6) de combinações possíveis.

**Mitigações implementadas neste projeto:**

1. Registro do último uso do TOTP
2. Validação temporal para evitar reutilização
3. Limite de tentativas (recomendado implementar)

### Outras Considerações de Segurança

- As chaves secretas são armazenadas de forma criptografada no banco de dados
- A comunicação deve ser feita sobre HTTPS
- É importante manter o relógio do servidor sincronizado

## Configuração do Projeto

1. Clone o repositório
2. Crie um arquivo `.env` com:
   ```
   DATABASE_URL=sqlite:///./totp.db
   ENCRYPTION_KEY=[sua_chave_fernet_base64]
   ```
3. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
4. Execute o servidor:
   ```bash
   uvicorn app.main:app --reload
   ```

## Testes

O projeto inclui testes automatizados que cobrem os fluxos principais:
- Geração de segredo
- Validação de TOTP válido
- Validação de TOTP inválido

Para executar os testes:
```bash
pytest
```

## Referências

- [RFC 6238](https://tools.ietf.org/html/rfc6238) - TOTP: Time-Based One-Time Password Algorithm
- [RFC 4226](https://tools.ietf.org/html/rfc4226) - HOTP: An HMAC-Based One-Time Password Algorithm