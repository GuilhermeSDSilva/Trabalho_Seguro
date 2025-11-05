# 💬 Trabalho Seguro - Chat Criptografado E2EE

Este projeto é um aplicativo de **chat seguro** que implementa **criptografia de ponta a ponta (E2EE)** usando o criptossistema **Paillier** e **assinaturas digitais**.

O **servidor (backend)** atua apenas como um retransmissor de mensagens cifradas, garantindo que ele **nunca tenha acesso ao conteúdo das conversas**.

---

## 🚀 Recursos Principais de Segurança

- 🔐 **Criptografia de Ponta a Ponta:**  
  Todas as mensagens são criptografadas no cliente (`frontend/app.py`) antes de serem enviadas.  
  O servidor (`backend/server_socketio.py`) apenas encaminha dados que **não pode ler**.

- ✍️ **Assinaturas Digitais:**  
  Cada mensagem é **assinada com a chave privada do remetente** (`paillier_sign`) e **verificada pelo destinatário** (`paillier_verify`).  
  Isso garante:
  - Autenticidade → prova de quem enviou.  
  - Integridade → prova de que a mensagem não foi alterada.

- 🗝️ **Persistência de Identidade:**  
  O cliente salva sua identidade (chaves pública e privada) em um arquivo `.key` local na pasta `frontend/keys/`.  
  Isso permite o "login" sem precisar gerar novas chaves a cada vez.

- 👥 **Grupos Públicos e Privados:**  
  Suporte para criar grupos onde **qualquer um pode entrar (public)** ou grupos que **exigem convite (private)**.

---

## 📂 Estrutura do Projeto

Trabalho_Seguro/
├── paillier.py (Biblioteca de Criptografia)
├── requirements.txt (Dependências do projeto)
├── backend/
│ └── server_socketio.py (O Servidor)
└── frontend/
├── app.py (O Cliente Streamlit)
└── keys/
└── (Aqui serão salvos os arquivos .key dos usuários)

---

## ⚙️ Instalação

Clone este repositório e instale todas as dependências necessárias (incluindo **Flask**, **Socket.IO** e **Streamlit**):

```bash
pip install -r requirements.txt
```

## ▶️ Como Executar

Você precisará de **dois terminais** abertos para rodar o projeto.

---

### 🖥️ 1. Terminal 1: Iniciar o Backend (Servidor)

Navegue até a pasta `backend` e execute o servidor:

```bash
cd backend
python server_socketio.py
```
O servidor será iniciado e ficará aguardando conexões na porta 5000.

💻 2. Terminal 2: Iniciar o Frontend (Cliente)
Navegue até a pasta frontend e execute a aplicação Streamlit:

```bash
Copiar código
cd frontend
streamlit run app.py
```

Isso abrirá automaticamente uma aba no seu navegador com a interface do chat.

⌨️ Como Usar a Aplicação

1️⃣ Login ou Registro

Ao abrir a aplicação, você verá uma tela de "Login ou Registro".

🔸 Para Registrar:

Digite um nome de usuário inédito e clique em "Entrar / Registrar".

O aplicativo irá:

Gerar seu par de chaves (Pública e Privada).

Salvar sua identidade no arquivo frontend/keys/nome.key.

Registrar sua chave pública no servidor.

🔹 Para Logar:
Digite o nome de usuário existente.
O app irá carregar seu .key salvo e reconectar sua identidade.

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






