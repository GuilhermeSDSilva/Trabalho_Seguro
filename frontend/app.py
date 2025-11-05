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

# --- NOVO: Definir a pasta de chaves ---
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
                self.put_system_message(f"[Registrado com sucesso] {data.get('note', '')}")
                self.register_status = "success"
            
            self.register_event.set()

        @self.sio.on('message')
        def on_message(data):
            try:
                sender_id = data.get('from')
                if sender_id == self.user_id:
                    return 
                
                sender_alias = data.get('alias', sender_id[:8])
                signature = data.get('signature')
                c = int(data.get('cipher'))
                length = int(data.get('len'))
                
                dec = paillier_decrypt(self.priv, c)
                
                try:
                    msg_bytes = dec.to_bytes(length, 'big')
                    msg = msg_bytes.decode(errors='replace')
                except OverflowError:
                    self.put_system_message(f"[ERRO Criptográfico] Falha ao decodificar mensagem de {sender_alias}.")
                    return

                if sender_id != 'SYSTEM':
                    sender_pub = self._get_user_pubkey(sender_id)
                    
                    if not sender_pub:
                        self.put_system_message(f"[ERRO DE SEGURANÇA] Chave pública de {sender_alias} não encontrada. Mensagem Descartada.")
                        return

                    if not signature:
                        self.put_system_message(f"[ALERTA DE SEGURANÇA] Mensagem de {sender_alias} não possui assinatura. Mensagem Descartada.")
                        return

                    is_valid = paillier_verify(sender_pub, signature, msg_bytes)

                    if not is_valid:
                        self.put_system_message(f"[ALERTA DE SEGURANÇA] Mensagem de {sender_alias} falhou na verificação de assinatura! Mensagem Descartada.")
                        return
                
                group_name = data.get('group')
                display_sender = f"{sender_alias}"
                if group_name:
                    display_sender += f" (no #{group_name})"
                
                if sender_id == 'SYSTEM':
                    self.put_system_message(f"[{display_sender}] {msg}")
                else:
                    self.put_chat_message(msg, display_sender, "user")

            except Exception as e:
                self.put_system_message(f"[ERRO AO PROCESSAR MENSAGEM] {e}")

        # ... (O resto dos handlers 'on_..._response' são iguais) ...
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
    
    # --- Funções de Mensagem (iguais) ---
    def put_chat_message(self, content, sender, avatar):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.message_queue.put({
            "content": content, "sender": sender, "avatar": avatar, 
            "timestamp": now, "type": "chat"
        })
    def put_system_message(self, content):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.message_queue.put({
            "content": content, "sender": "Sistema", "avatar": "assistant", 
            "timestamp": now, "type": "system"
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

    # *** FUNÇÕES DE IDENTIDADE MODIFICADAS ***

    def get_key_filename(self, alias):
        """Gera o caminho completo para o arquivo .key"""
        # Gera um nome de arquivo seguro
        filename = f"{''.join(c for c in alias if c.isalnum())}.key"
        # Retorna o caminho completo (ex: keys/Jico.key)
        return os.path.join(KEYS_DIR, filename)

    def save_identity(self):
        """Salva a identidade atual em um arquivo .key dentro da pasta KEYS_DIR"""
        if not self.alias:
            return
        
        filename = self.get_key_filename(self.alias)
        
        # --- MUDANÇA AQUI ---
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
        
        # --- MUDANÇA AQUI ---
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

    # *** LÓGICA DE LOGIN (Sem mudanças, mas é importante) ***
    # (Esta função já usa as funções modificadas, então funcionará)
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

    # --- Funções de Envio de Mensagem (Sem mudanças) ---
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
            msg_bytes = msg.encode()
            m_int = int.from_bytes(msg_bytes, 'big')
            signature = paillier_sign(self.priv, msg_bytes)
            
            users = requests.get(f"{API}/users").json()['users']
            sent_count = 0
            
            for u in users:
                pk = u['pub_key']
                e_val = int(pk.get('e', 65537))
                pub_to = Pub(int(pk['n']), int(pk['g']), int(pk['n2']), e_val)
                cipher = paillier_encrypt(pub_to, m_int)
                
                self.sio.emit('send_group', {
                    'group': group,
                    'from_id': self.user_id,
                    'cipher': str(cipher),
                    'length': len(msg_bytes),
                    'signature': signature,
                    'to_id': u['user_id']
                })
                sent_count += 1
            
            if sent_count > 0:
                self.put_chat_message(msg, f"Você para #{group}", "user")
            else:
                self.put_system_message("[Erro de Envio] Não há usuários online para criptografar a mensagem de grupo.")
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


# --- Interface Streamlit (Sem NENHUMA alteração necessária aqui) ---
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

    while not st.session_state.message_queue.empty():
        msg = st.session_state.message_queue.get()
        if msg.get("type") == "chat":
            st.session_state.chat_messages.append(msg)
        else:
            st.session_state.system_notifications.append(msg)
        
    # --- Tela de Login ---
    if not client.alias:
        st.title("Trabalho Seguro - Login ou Registro")
        alias_input = st.text_input("Seu nome de usuário:", key="alias_input", 
                                  help="Se o nome já existir localmente, fará login. Se não, tentará registrar.")
        
        if st.button("Entrar / Registrar"):
            if alias_input:
                with st.spinner("Conectando..."):
                    if client.login(alias_input):
                        st.session_state.users = requests.get(f"{API}/users").json().get('users', [])
                        st.session_state.groups = requests.get(f"{API}/groups").json().get('groups', [])
                        st.rerun() 
                    else:
                        # Erro já foi postado nas notificações
                        pass
            else:
                st.error("Por favor, insira um nome de usuário.")
    
    # --- Tela Principal do Chat ---
    else:
        st.sidebar.title(f"Logado como: {client.alias[:20]}")
        st.sidebar.caption(f"ID: {client.user_id[:8]}-...")
        
        # Botão de Logout
        if st.sidebar.button("Sair (Deslogar)", use_container_width=True, type="primary"):
            try:
                client.sio.disconnect()
                client.put_system_message("Você foi desconectado.")
            except Exception as e:
                print(f"Erro ao desconectar: {e}")
            
            keys_to_clear = ["client", "message_queue", "chat_messages", "system_notifications", "users", "groups"]
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