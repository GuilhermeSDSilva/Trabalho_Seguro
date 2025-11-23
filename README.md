# 💬 Trabalho Seguro - Chat Criptografado E2EE com 2FA

Este projeto é uma aplicação de **chat seguro** que implementa **Criptografia de Ponta a Ponta (E2EE)** utilizando o criptossistema homomórfico **Paillier**, **Assinaturas Digitais** para autenticidade e **Autenticação de Dois Fatores (2FA)** para proteção de acesso.

O **Backend** atua estritamente como um retransmissor de mensagens cifradas, garantindo que o servidor **nunca tenha acesso ao conteúdo das conversas** (Zero-Knowledge Architecture).

---

## 🚀 Recursos de Segurança

### 1. 🔐 Criptografia de Ponta a Ponta (Paillier)
Todas as mensagens são cifradas no cliente (`frontend`) antes de saírem para a rede. O servidor apenas armazena e repassa números gigantes cifrados que não consegue decifrar.

### 2. 🛡️ Autenticação de Dois Fatores (2FA)
Implementação de **TOTP (Time-based One-Time Password)**.
- Ao registrar, o sistema gera um **QR Code** único.
- O login exige um código de 6 dígitos gerado pelo seu telemóvel (Google Authenticator/Authy).
- Isso impede que alguém acesse a conta mesmo se roubar o ficheiro de chaves local.

### 3. ✍️ Assinaturas Digitais
Cada mensagem enviada é assinada digitalmente com a chave privada do remetente. O destinatário verifica matematicamente a assinatura para garantir:
- **Autenticidade:** A mensagem veio realmente de quem diz ser.
- **Integridade:** O conteúdo não foi alterado no caminho.

### 4. 👁️ Monitoramento (Watchdog)
O servidor possui um sistema de **Watchdog** que monitora o processo principal. Se o servidor cair ou travar, ele é reiniciado automaticamente em segundos.

---

## 📋 Pré-requisitos

- **Python 3.11+** instalado.
- **Google Authenticator** (ou Authy/Microsoft Authenticator) instalado no seu telemóvel.

---

## 📂 Estrutura do Projeto

```text
Trabalho_Seguro/
├── paillier.py             # Biblioteca matemática (Criptografia Paillier)
├── requirements.txt        # Dependências do projeto
├── backend/
│   ├── server_socketio.py  # Servidor WebSocket (Lógica principal)
│   ├── watchdog.py         # Monitor de disponibilidade (Inicia o servidor)
│   ├── client_socketio.py  # Cliente CLI (Terminal) alternativo ao Streamlit
│   └── chat_seguro.db      # Base de dados (Apenas metadados e cifras)
├── frontend/
│   ├── app.py              # Cliente Gráfico Principal (Streamlit)
│   ├── leitor_chaves.py    # Utilitário para inspecionar ficheiros .key
│   └── keys/               # Identidades locais (.key) e histórico de chat
└── README.md
```
---

## ⚙️ Instalação

Quando tiver terminado de clonar este repositório:

1. Criar e ativar um ambiente virtual

No Windows: 

```bash
python -m venv venv
venv\Scripts\Activate
```

No Linux/Mac

```bash
python3 -m venv venv
source venv/bin/activate
```
  
2. Instale todas as dependências necessárias (incluindo **Flask**, **Socket.IO** e **Streamlit**):

```bash
pip install -r requirements.txt
```

## ▶️ Como Executar

Você precisará de no mínimo **dois terminais** abertos, ambos rodando o ambiente virtual.

---

### 🖥️ 1. Terminal 1: Iniciar o Backend (Servidor)

Navegue até a pasta `backend` e execute o Watchdog:

```bash
cd backend
python watchdog.py
```

O servidor será iniciado e ficará aguardando conexões na porta 5000.

### 💻 2. Terminal 2: Iniciar o Frontend (Cliente)
Navegue até a pasta frontend e execute a aplicação Streamlit:

```bash
cd frontend
streamlit run app.py
```

O navegador abrirá automaticamente a interface do chat.

## Como Usar a Aplicação

### Primeiro Acesso (Registro + 2FA)

1. Na tela inicial, digite um Nome de Usuário (Alias) inédito.

2. Clique em "Entrar / Registrar".

3. O sistema irá gerar suas chaves criptográficas (pode levar alguns segundos).

**IMPORTANTE:** Um QR Code aparecerá na tela.

4. Abra o Google Authenticator no celular, escolha "Ler código QR" e aponte para a tela.

5. Digite o código de 6 dígitos gerado pelo app no campo "Token 2FA" e clique em verificar.

*Caminho Alternativo*

4. Abra o Google Authenticator no celular, escolha "Inserir chave de configuração".

5. Dê um codinome a chave, digite a chave que aparece na tela e selecione a opção Tipo de Chave "Baseada no horário"

6. Digite o código de 6 dígitos gerado pelo app no campo "Token 2FA" e clique em verificar.

**OBS:** O algoritmo TOTP (2FA) depende da hora exata. Se o relógio do seu computador ou do celular estiverem adiantados/atrasados em mais de 30 segundos, o código falhará.
Caso isso aconteça, sincronize o horário de sua máquina com o de seu celular

### Login Recorrente

1. Digite seu nome de usuário já registrado.

2. O sistema detectará sua identidade local (.key).

3. Digite o código atual do seu autenticador (Google Authenticator) para liberar o acesso.

2️⃣ Interface Principal

💬 Chat:
A tela principal exibe as mensagens de grupos e privadas.

🧭 Barra Lateral (Sidebar):
Mostra quem você é e seu ID.

Sair (Deslogar): desconecta e volta à tela de login.

Atualizar Listas: atualiza as listas de usuários online e grupos disponíveis.

🔔 Notificações do Sistema:

Localizado abaixo do chat.
Mostra logs e mensagens do sistema como:

"Conectado"

"Erro"

"Usuário entrou no grupo"

Logs de geração de chaves

3️⃣ Enviando Mensagens e Comandos
Todos os comandos são digitados na caixa de texto inferior do chat.

Tipo de Mensagem	Sintaxe	Exemplo
💬 Privada	@usuario:mensagem	@ana:Oi, tudo bem?
👥 Grupo	#grupo:mensagem	#devs:Bom dia, pessoal!
➕ Criar grupo público	/create nome_do_grupo	/create geral
🔒 Criar grupo privado	/create nome_do_grupo private	/create equipe private
🚪 Entrar em grupo	/join nome_do_grupo	/join geral
✉️ Convidar usuário	/invite nome_do_grupo nome_do_usuario	/invite equipe joao
❌ Sair do grupo	/leave nome_do_grupo	/leave geral

🛡️ Resumo Final:
Este projeto garante confidencialidade, autenticidade e integridade nas comunicações,
com criptografia Paillier e assinaturas digitais, mantendo o servidor cego para o conteúdo das mensagens.






