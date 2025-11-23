import streamlit as st
import socketio
import requests
import uuid
import datetime
import threading
import queue
import time
import pickle
import os
import sys
import json
import qrcode
from io import BytesIO
import base64

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from paillier import (
        paillier_keygen, 
        paillier_encrypt, 
        paillier_decrypt, 
        Pub, Priv,
        paillier_sign, 
        paillier_verify
    )
except ImportError:
    st.error("ERRO: O arquivo 'paillier.py' não foi encontrado. Coloque-o na mesma pasta.")
    st.stop()

# --- Configurações do Servidor ---
API = "http://127.0.0.1:5000"
WS = "http://127.0.0.1:5000"

# --- Definir a pasta de chaves ---
KEYS_DIR = "keys"

# --- Classe Cliente Modificada ---
class SecureChatClient:
    def __init__(self, message_queue):
        self.sio = socketio.Client()
        self.message_queue = message_queue
        
        self.user_id = None
        self.priv = None
        self.pub = None
        self.alias = None
        self.user_key_cache = {} 
        self.lock = threading.Lock()

        self.is_logged_in = False       # Novo controlo de estado real
        self.waiting_for_2fa = False    # Indica se a UI deve mostrar o input de código
        self.new_totp_secret = None     # Para guardar o segredo temporário no registo
        
        self.register_event = threading.Event()
        self.register_status = ""
        
        self.register_handlers()

    def register_handlers(self):
        
        @self.sio.event
        def connect():
            self.put_system_message("[Conectado ao servidor]")
            if self.user_id and self.alias and self.pub:
                pub_obj = {"n": str(self.pub.n), "g": str(self.pub.g), "n2": str(self.pub.n2), "e": str(self.pub.e)}
                self.sio.emit('register', {
                    'user_id': self.user_id,
                    'alias': self.alias,
                    'pub_key': pub_obj
                })

        @self.sio.on('register_response')
        def on_register_response(data):
            if data.get('error'):
                self.put_system_message(f"[Erro de Registro] {data['error']}")
                self.register_status = data['error']
            else:
                self.put_system_message(f"[Registrado] {data.get('note', '')}")

                # SE O SERVIDOR MANDAR UM SEGREDO NOVO (NOVO REGISTO)
                if data.get('totp_secret'):
                    self.new_totp_secret = data.get('totp_secret')
                    self.put_system_message("IMPORTANTE: Configure o seu 2FA agora!")
                
                # Após registar/reconectar, o servidor espera o 2FA
                self.register_status = "success"
                self.waiting_for_2fa = True 
                self.register_event.set()

        @self.sio.on('login_success')
        def on_login_success(data):
            self.is_logged_in = True
            self.waiting_for_2fa = False
            self.new_totp_secret = None  # Limpa o segredo da memória
            self.put_system_message(f"Autenticação 2FA aceite! Bem-vindo {data.get('alias')}.")

        @self.sio.on('auth_fail')
        def on_auth_fail(data):
            self.put_system_message(f"[FALHA 2FA] {data.get('msg')}")
            # Não muda o estado, permite tentar de novo

        @self.sio.on('message')
        def on_message(data):
            try:
                sender_id = data.get('from')
                if sender_id == self.user_id:
                    return 
                
                if sender_id == 'SYSTEM':
                    content = data.get('content')
                    group = data.get('group')
                    
                    sender_display = "SISTEMA"
                    if group:
                        sender_display += f" (no #{group})"
                    
                    self.put_system_message(f"[{sender_display}] {content}")
                    return 
                
                sender_alias = data.get('alias')
                if not sender_alias:
                    sender_alias = self._resolve_sender_name(sender_id)
                # --------------------------------------------------------

                signature = data.get('signature')
                c = int(data.get('cipher'))
                length = int(data.get('len'))
                
                # Descriptografia
                dec = paillier_decrypt(self.priv, c)
                
                try:
                    msg_bytes = dec.to_bytes(length, 'big')
                    msg = msg_bytes.decode(errors='replace')
                except OverflowError:
                    self.put_system_message(f"[ERRO] Falha ao decodificar msg de {sender_alias}.")
                    return

                # Verificação de Assinatura
                if sender_id != 'SYSTEM':
                    sender_pub = self._get_user_pubkey(sender_id)
                    
                    if not sender_pub:
                        self.put_system_message(f"[ERRO] Chave pública de {sender_alias} não encontrada.")
                        return

                    if not signature:
                        self.put_system_message(f"[ALERTA] Msg de {sender_alias} sem assinatura.")
                        return

                    is_valid = paillier_verify(sender_pub, signature, msg_bytes)

                    if not is_valid:
                        self.put_system_message(f"[ALERTA] Assinatura falsa de {sender_alias}!")
                        return
                
                # Formatar nome para exibição
                group_name = data.get('group')
                display_sender = f"{sender_alias}"
                
                if group_name:
                    display_sender += f" (no #{group_name})"
                
                if sender_id == 'SYSTEM':
                    self.put_system_message(f"[{display_sender}] {msg}")
                else:
                    # Agora passamos o 'display_sender' que contém o NOME correto, não o ID
                    self.put_chat_message(msg, display_sender, "user", signature=signature)

            except Exception as e:
                self.put_system_message(f"[ERRO AO PROCESSAR MENSAGEM] {e}")

        @self.sio.on('send_response')
        def on_send_response(data):
            if data.get('error'):
                self.put_system_message(f"[Erro ao Enviar] {data['error']}")
        @self.sio.on('create_group_response')
        def on_create_group_response(data):
            if data.get('error'):
                self.put_system_message(f"[Erro ao Criar Grupo] {data['error']}")
            else:
                self.put_system_message(f"[Grupo Criado] {data['group']} (Privacidade: {data.get('privacy', 'public')})")
        @self.sio.on('join_group_response')
        def on_join_group_response(data):
            if data.get('error'):
                self.put_system_message(f"[Erro ao Entrar no Grupo] {data['error']}")
            else:
                self.put_system_message(f"[Entrou no Grupo] {data['group']}")
        @self.sio.on('leave_group_response')
        def on_leave_group_response(data):
            if data.get('error'):
                self.put_system_message(f"[Erro ao Sair do Grupo] {data['error']}")
            else:
                self.put_system_message(f"[Saiu do Grupo] {data['group']}")
        @self.sio.on('invite_response')
        def on_invite_response(data):
            if data.get('error'):
                self.put_system_message(f"[Erro ao Convidar] {data['error']}")
            else:
                self.put_system_message(f"[Convite enviado para {data['invited']} (Grupo: {data['group']})")
        @self.sio.event
        def disconnect():
            self.put_system_message("[Desconectado do servidor]")
    
    # --- Funções de Mensagem  ---
    def put_system_message(self, content):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.message_queue.put({
            "content": content, 
            "sender": "Sistema", 
            "avatar": "assistant", 
            "timestamp": now, 
            "type": "system"
        })

    def put_chat_message(self, content, sender, avatar, signature=None):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.message_queue.put({
            "content": content, 
            "sender": sender, 
            "avatar": avatar, 
            "timestamp": now, 
            "type": "chat",
            "signature": signature # Importante para deduplicação
        })

    # --- Funções Auxiliares ---
    def _get_user_pubkey(self, user_id):
        if user_id in self.user_key_cache:
            return self.user_key_cache[user_id]
        try:
            users = requests.get(f"{API}/users").json()['users']
            for u in users:
                pk = u['pub_key']
                e_val = int(pk.get('e', 65537))
                pub_obj = Pub(int(pk['n']), int(pk['g']), int(pk['n2']), e_val)
                self.user_key_cache[u['user_id']] = pub_obj
            return self.user_key_cache.get(user_id)
        except Exception as e:
            self.put_system_message(f"Erro ao buscar chaves públicas: {e}")
            return None

    def get_key_filename(self, alias):
        """Gera o caminho completo para o arquivo .key"""
        # Gera um nome de arquivo seguro
        filename = f"{''.join(c for c in alias if c.isalnum())}.key"
        # Retorna o caminho completo (ex: keys/Jico.key)
        return os.path.join(KEYS_DIR, filename)
    
    def submit_2fa(self, token):
        if self.user_id:
            self.sio.emit('login_2fa', {
                'user_id': self.user_id, 
                'token': token
            })

    def save_identity(self):
        """Salva a identidade atual em um arquivo .key dentro da pasta KEYS_DIR"""
        if not self.alias:
            return
        
        filename = self.get_key_filename(self.alias)
        
        # Garante que a pasta 'keys' exista
        os.makedirs(KEYS_DIR, exist_ok=True)
        
        identity_data = {
            "user_id": self.user_id,
            "alias": self.alias,
            "pub": self.pub,
            "priv": self.priv
        }
        try:
            with open(filename, 'wb') as f:
                pickle.dump(identity_data, f)
            self.put_system_message(f"Identidade salva em {filename}")
        except Exception as e:
            self.put_system_message(f"Erro ao salvar identidade: {e}")

    def load_identity(self, alias):
        """Tenta carregar uma identidade de um arquivo .key da pasta KEYS_DIR"""
        filename = self.get_key_filename(alias)
        
        # Garante que a pasta 'keys' exista (para evitar erro ao verificar)
        os.makedirs(KEYS_DIR, exist_ok=True)
        
        if not os.path.exists(filename):
            return False
            
        try:
            with open(filename, 'rb') as f:
                identity_data = pickle.load(f)
            
            self.user_id = identity_data["user_id"]
            self.alias = identity_data["alias"]
            self.pub = identity_data["pub"]
            self.priv = identity_data["priv"]
            
            self.put_system_message(f"Identidade de {self.alias} carregada de {filename}.")
            return True
        except Exception as e:
            self.put_system_message(f"Erro ao carregar identidade {filename}: {e}")
            return False
        
    def _resolve_sender_name(self, user_id):
        """Busca na API quem é o dono deste ID para mostrar o nome correto"""
        try:
            # Busca a lista de usuários do servidor
            resp = requests.get(f"{API}/users")
            if resp.status_code == 200:
                users = resp.json().get('users', [])
                for u in users:
                    if u['user_id'] == user_id:
                        return u['alias']
        except Exception as e:
            print(f"Erro ao resolver nome: {e}")
        
        # Se não achar (ou der erro), retorna os 8 primeiros digitos do ID
        return user_id[:8]

    # LÓGICA DE LOGIN 
    def login(self, alias):
        with self.lock:
            if self.alias:
                return True
            
            self.register_event.clear()
            self.register_status = ""
            is_new_registration = False

            if not self.load_identity(alias):
                is_new_registration = True
                self.put_system_message("Nenhuma identidade local encontrada. Tentando novo registro...")
                
                self.put_system_message(f"[{alias}] Gerando novas chaves Paillier (pode demorar)...")
                self.pub, self.priv = paillier_keygen()
                
                self.put_system_message("---------------------------------")
                self.put_system_message("Processo de Geração de Chaves (Cliente):")
                self.put_system_message("1. Chave Pública (Pub) gerada:")
                self.put_system_message(f"   - n (módulo): {str(self.pub.n)[:25]}...")
                self.put_system_message(f"   - g (gerador): {str(self.pub.g)[:25]}...")
                self.put_system_message(f"   - e (expoente RSA): {self.pub.e}")
                self.put_system_message("2. Chave Privada (Priv) gerada:")
                self.put_system_message("   - d (expoente RSA): [SECRETO, MANTIDO NO CLIENTE]")
                self.put_system_message("   - mu (inverso Paillier): [SECRETO, MANTIDO NO CLIENTE]")
                self.put_system_message("3. Enviando Chave Pública para o servidor...")
                self.put_system_message("---------------------------------")
                
                self.alias = alias
                self.user_id = str(uuid.uuid4())
                
                self.save_identity()
            
            try:
                self.sio.connect(WS)
            except Exception as e:
                self.put_system_message(f"Erro ao conectar ao servidor: {e}")
                return False

            if not self.register_event.wait(timeout=10.0):
                self.put_system_message("Erro: Servidor não respondeu ao registro.")
                self.sio.disconnect()
                return False

            if self.register_status == "success":
                return True
            else:
                if is_new_registration:
                    try:
                        # Remove a chave inválida da pasta 'keys'
                        os.remove(self.get_key_filename(alias))
                        self.put_system_message("Removendo identidade local inválida (nome em uso).")
                    except Exception as e:
                        self.put_system_message(f"Erro ao remover chave inválida: {e}")
                
                self.sio.disconnect()
                self.alias = None
                self.user_id = None
                self.pub = None
                self.priv = None
                return False

    # --- Funções de Envio de Mensagem ---
    def send_dm(self, target_alias, msg):
        try:
            users = requests.get(f"{API}/users").json()['users']
            target = next((u for u in users if u['alias'] == target_alias), None)
            
            if not target:
                self.put_system_message(f"Erro: Usuário '{target_alias}' não encontrado.")
                return

            pk = target['pub_key']
            pub_to = Pub(int(pk['n']), int(pk['g']), int(pk['n2']), int(pk['e']))
            
            msg_bytes = msg.encode()
            m_int = int.from_bytes(msg_bytes, 'big')
            cipher = paillier_encrypt(pub_to, m_int)
            signature = paillier_sign(self.priv, msg_bytes)

            self.sio.emit('send', {
                'from_id': self.user_id,
                'to_id': target['user_id'],
                'cipher': str(cipher),
                'length': len(msg_bytes),
                'signature': signature
            })
            self.put_chat_message(msg, f"Você para @{target_alias}", "user")
        except Exception as e:
            self.put_system_message(f"Erro ao enviar DM: {e}")

    def send_group_message(self, group, msg):
        try:
            # 1. Buscar membros do grupo especificamente (rota existente no server)
            resp = requests.get(f"{API}/groups/{group}/members")
            if resp.status_code != 200:
                self.put_system_message(f"Erro ao buscar membros do grupo: {resp.text}")
                return
            
            members = resp.json().get('members', [])
            
            # 2. Preparar dados
            msg_bytes = msg.encode()
            m_int = int.from_bytes(msg_bytes, 'big')
            signature = paillier_sign(self.priv, msg_bytes)
            
            # Buscar chaves públicas de todos os usuários para cruzar com os membros
            all_users = requests.get(f"{API}/users").json()['users']
            users_map = {u['user_id']: u for u in all_users}
            
            bundle = {}
            sent_count = 0
            
            # 3. Criptografar para cada membro do grupo
            for member_id in members:
                # Pula o próprio remetente (opcional, mas economiza processamento)
                if member_id == self.user_id:
                    continue
                
                user_data = users_map.get(member_id)
                if not user_data:
                    continue

                pk = user_data['pub_key']
                # Garante que os valores são inteiros
                e_val = int(pk.get('e', 65537))
                pub_to = Pub(int(pk['n']), int(pk['g']), int(pk['n2']), e_val)
                
                cipher = paillier_encrypt(pub_to, m_int)
                
                # Adiciona ao bundle: { user_id: { 'c': cifrado, 'l': tamanho } }
                bundle[member_id] = {'c': str(cipher), 'l': len(msg_bytes)}
                sent_count += 1
            
            if sent_count > 0:
                # 4. Enviar UM ÚNICO evento com o 'bundle' completo
                self.sio.emit('send_group', {
                    'group': group,
                    'from_id': self.user_id,
                    'bundle': bundle,   # O servidor espera este campo
                    'signature': signature
                })
                self.put_chat_message(msg, f"Você para #{group}", "user", signature=signature)
            else:
                self.put_system_message(f"Não há outros membros no grupo '{group}' para receber a mensagem.")
                
        except Exception as e:
            self.put_system_message(f"Erro ao enviar para grupo: {e}")

    def run_command(self, prompt):
        cmd_parts = prompt.split(' ', 1)
        cmd = cmd_parts[0]
        args = cmd_parts[1] if len(cmd_parts) > 1 else ""

        try:
            if cmd == '/create':
                privacy = 'public'
                group_name = args
                if args.lower().endswith(' private'):
                    privacy = 'private'
                    group_name = args[:-len(' private')].strip()
                if not group_name:
                    self.put_system_message("Formato: /create <nome_grupo> [private]")
                    return
                self.sio.emit('create_group', {'group': group_name, 'user_id': self.user_id, 'privacy': privacy})
            elif cmd == '/join':
                if not args:
                    self.put_system_message("Formato: /join <nome_grupo>")
                    return
                self.sio.emit('join_group', {'group': args, 'user_id': self.user_id})
            elif cmd == '/leave':
                if not args:
                    self.put_system_message("Formato: /leave <nome_grupo>")
                    return
                self.sio.emit('leave_group', {'group': args, 'user_id': self.user_id})
            elif cmd == '/invite':
                if ' ' not in args:
                    self.put_system_message("Formato: /invite <nome_grupo> <nome_usuario>")
                    return
                group, target_alias = args.rsplit(' ', 1)
                self.sio.emit('invite_user', {'group': group.strip(), 'from_id': self.user_id, 'target_alias': target_alias.strip()})
            else:
                self.put_system_message(f"Comando desconhecido: {cmd}")
        except Exception as e:
            self.put_system_message(f"Erro ao processar comando: {e}")

# ----- Funções de armazenamento -----
def get_history_file(alias):
    # Salva na pasta keys para manter organizado, ou na raiz
    return os.path.join("keys", f"history_{alias}.json")

def save_history(alias, messages):
    if not alias: return
    try:
        with open(get_history_file(alias), 'w', encoding='utf-8') as f:
            json.dump(messages, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Erro ao salvar histórico: {e}")

def load_history(alias):
    if not alias: return []
    path = get_history_file(alias)
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Erro ao carregar histórico: {e}")
    return []


# --- Interface Streamlit  ---
def main():
    st.set_page_config(page_title="Chat Seguro", layout="wide")

    if "client" not in st.session_state:
        st.session_state.message_queue = queue.Queue()
        st.session_state.client = SecureChatClient(st.session_state.message_queue)
        st.session_state.chat_messages = []
        st.session_state.system_notifications = []
        st.session_state.users = []
        st.session_state.groups = []

    client = st.session_state.client

    # --- PROCESSAMENTO DA FILA COM DEDUPLICAÇÃO E SALVAMENTO ---
    while not st.session_state.message_queue.empty():
        msg = st.session_state.message_queue.get()
        
        if msg.get("type") == "chat":
            # Deduplicação: Verifica se já existe mensagem com mesma assinatura
            # O servidor reenvia histórico de grupos ao reconectar, então isso é vital.
            is_duplicate = False
            new_sig = msg.get("signature")
            
            if new_sig: # Só verifica se tiver assinatura
                for old_msg in st.session_state.chat_messages:
                    if old_msg.get("signature") == new_sig:
                        is_duplicate = True
                        break
            
            if not is_duplicate:
                st.session_state.chat_messages.append(msg)
                # Salvar histórico sempre que chegar mensagem nova e tivermos um alias logado
                if client.alias:
                    save_history(client.alias, st.session_state.chat_messages)
                    
        else:
            st.session_state.system_notifications.append(msg)
        
    # --- Tela de Login ---
    # CASO 1: Utilizador ainda não iniciou o processo de Login/Registo
    if not client.alias:
        st.title("Trabalho Seguro - Login ou Registo")
        alias_input = st.text_input("Seu nome de utilizador:", key="alias_input")
        
        if st.button("Entrar / Registar"):
            if alias_input:
                with st.spinner("A conectar..."):
                    if client.login(alias_input):
                        st.rerun()
            else:
                st.error("Por favor, insira um nome de utilizador.")

# CASO 2: Conectado, mas aguardando 2FA (Verificação)
    elif client.waiting_for_2fa and not client.is_logged_in:
        st.title("Autenticação de Dois Fatores (2FA)")
        
        # --- MOSTRAR ERROS DO SISTEMA AQUI ---
        if st.session_state.system_notifications:
            last_msg = st.session_state.system_notifications[-1]
            # Mostra erro se a última notificação for de falha
            if "FALHA" in last_msg['content'] or "Invalid" in last_msg['content']:
                st.error(f"{last_msg['content']}")
        # -------------------------------------

        # Se for um NOVO registo, mostramos o QR Code
        if client.new_totp_secret:
            st.warning("NOVO UTILIZADOR: Configure o seu autenticador agora!")
            st.write("Escaneie este QR Code com o Google Authenticator ou Authy:")
            
            # Gerar QR Code
            totp_uri = f"otpauth://totp/TrabalhoSeguro:{client.alias}?secret={client.new_totp_secret}&issuer=TrabalhoSeguro"
            qr = qrcode.make(totp_uri)
            img_byte_arr = BytesIO()
            qr.save(img_byte_arr, format='PNG')
            st.image(img_byte_arr.getvalue(), caption="Scan-me")
            
            st.code(client.new_totp_secret, language="text")
            st.info("Ou digite o código acima manualmente na sua aplicação.")
            st.divider()

        st.subheader("Digite o código de 6 dígitos:")

        # --- CORREÇÃO AQUI: USAR FORMULÁRIO ---
        with st.form("form_2fa"):
            token_input = st.text_input("Token 2FA", max_chars=6, key="token_input_form")
            submitted = st.form_submit_button("Verificar Código", type="primary")
            
            if submitted:
                if token_input:
                    client.submit_2fa(token_input)
                    st.toast("A verificar...", icon="⏳")
                    # Pequeno atraso para dar tempo ao WebSocket de enviar e receber a resposta
                    time.sleep(1)
                    st.rerun()
                else:
                    st.warning("Por favor, digite o código.")

# CASO 3: Logado e Autenticado (Chat Normal)
    else:
        # --- CARREGAR HISTÓRICO SE NECESSÁRIO (Só faz uma vez) ---
        if not st.session_state.get('history_loaded'):
            history = load_history(client.alias)
            if history:
                st.session_state.chat_messages = history
            
            # Tenta carregar listas, sem bloquear se falhar
            try:
                st.session_state.users = requests.get(f"{API}/users").json().get('users', [])
                st.session_state.groups = requests.get(f"{API}/groups").json().get('groups', [])
            except Exception:
                pass
                
            st.session_state['history_loaded'] = True
    
        # --- Interface Principal do Chat (Agora dentro do else correto) ---
        st.sidebar.title(f"Logado como: {client.alias[:20]}")
        st.sidebar.caption(f"ID: {client.user_id[:8]}-...")
        
        # Botão de Logout
        if st.sidebar.button("Sair (Deslogar)", use_container_width=True, type="primary"):
            try:
                client.sio.disconnect()
            except Exception as e:
                print(f"Erro ao desconectar: {e}")
            
            # Limpa estado
            keys_to_clear = ["client", "message_queue", "chat_messages", "system_notifications", "users", "groups", "history_loaded"]
            for key in keys_to_clear:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()

        if st.sidebar.button("Atualizar Listas", use_container_width=True):
            try:
                st.session_state.users = requests.get(f"{API}/users").json().get('users', [])
                st.session_state.groups = requests.get(f"{API}/groups").json().get('groups', [])
                st.toast("Listas atualizadas!")
            except Exception as e:
                st.sidebar.error(f"Erro ao atualizar: {e}")

        st.sidebar.subheader("Usuários Online")
        if not st.session_state.users:
            st.sidebar.text("Ninguém online.")
        for u in st.session_state.users:
            st.sidebar.markdown(f"- **{u['alias']}** (`@{u['alias']}:msg`)")

        st.sidebar.subheader("Grupos Disponíveis")
        if not st.session_state.groups:
            st.sidebar.text("Nenhum grupo criado.")
        for g in st.session_state.groups:
            st.sidebar.markdown(f"- **{g['name']}** ({g['members']} membros, {g.get('privacy', 'public')}) (`#{g['name']}:msg`)")

        st.sidebar.subheader("Ajuda de Comandos")
        st.sidebar.markdown("""
        - `/create <nome> [private]`
        - `/join <nome>`
        - `/leave <nome>`
        - `/invite <grupo> <usuario>`
        """)

        st.title("Canal Principal")
        
        chat_container = st.container(height=500)
        with chat_container:
            for msg in st.session_state.chat_messages:
                with st.chat_message(msg["avatar"]):
                    st.markdown(f"**{msg['sender']}** ({msg['timestamp']})")
                    st.markdown(msg["content"])
        
        notifications = st.session_state.system_notifications
        notif_count = len(notifications)
        with st.expander(f"🔔 Notificações do Sistema ({notif_count})", expanded=False):
            if notif_count == 0:
                st.text("Nenhuma notificação.")
            else:
                with st.container(height=200):
                    for msg in reversed(notifications):
                        st.info(f"**{msg['timestamp']}**: {msg['content']}")

        prompt = st.chat_input("Digite @usuario:msg, #grupo:msg, ou /comando...")

        if prompt:
            try:
                if prompt.startswith('/'):
                    client.run_command(prompt)
                elif prompt.startswith('@'):
                    if ':' not in prompt:
                        client.put_system_message("Formato inválido. Use @usuario:mensagem")
                    else:
                        target_alias, msg = prompt[1:].split(':', 1)
                        if not target_alias or not msg:
                            client.put_system_message("Formato inválido. Use @usuario:mensagem")
                        else:
                            client.send_dm(target_alias.strip(), msg.strip())
                elif prompt.startswith('#'):
                    if ':' not in prompt:
                        client.put_system_message("Formato inválido. Use #grupo:mensagem")
                    else:
                        group, msg = prompt[1:].split(':', 1)
                        if not group or not msg:
                            client.put_system_message("Formato inválido. Use #grupo:mensagem")
                        else:
                            client.send_group_message(group.strip(), msg.strip())
                else:
                    client.put_system_message("Erro: Mensagens devem ser DMs (@usuario:msg) ou de Grupo (#grupo:msg).")
                st.rerun()
            except Exception as e:
                st.error(f"Erro ao processar input: {e}")
        
        time.sleep(1)
        st.rerun()

if __name__ == "__main__":
    main()