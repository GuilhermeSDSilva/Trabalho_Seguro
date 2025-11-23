import socketio
import requests
import uuid
import threading
import time
import datetime
import os
import sys
import sqlite3
import tempfile
import base64
import json

# NOVO (para senha da chave)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

import pyotp

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from paillier import paillier_keygen, paillier_encrypt, paillier_decrypt, Pub, paillier_sign, paillier_verify

API = "http://127.0.0.1:5000"
WS = "http://127.0.0.1:5000"

sio = socketio.Client()

user_id = None
priv = None
pub = None
alias = None

DB_PATH = "messages.db"
ENC_DB_PATH = DB_PATH + ".enc"
# KEY_DIR: tenta localizar as keys (frontend/keys ou backend/keys)
POSSIBLE_KEY_DIRS = [
    os.path.join(os.path.dirname(__file__), '..', 'frontend', 'keys'),
    os.path.join(os.path.dirname(__file__), 'keys'),
]
KEY_DIR = next((p for p in POSSIBLE_KEY_DIRS if os.path.exists(p)), POSSIBLE_KEY_DIRS[0])
os.makedirs(KEY_DIR, exist_ok=True)

# NOVO — chave Fernet criptografada por senha
KEY_ENC_PATH = os.path.join(KEY_DIR, "fernet.key.enc")
SALT_PATH = os.path.join(KEY_DIR, "salt.bin")

FERNET_INSTANCE = None  # será setado depois da senha


# ================================================================
# 🔐 Senha + derivação + descriptografia da chave Fernet
# ================================================================
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=400000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def init_master_key():
    """Cria a chave Fernet criptografada com senha na primeira execução."""
    os.makedirs(KEY_DIR, exist_ok=True)

    if os.path.exists(KEY_ENC_PATH):
        return  # já existe, não cria novamente

    print("Você está rodando pela primeira vez.")
    password = input("Crie uma senha para desbloquear o banco: ").strip()

    salt = os.urandom(16)
    with open(SALT_PATH, "wb") as f:
        f.write(salt)

    derived = derive_key_from_password(password, salt)
    protector = Fernet(derived)

    real_key = Fernet.generate_key()

    with open(KEY_ENC_PATH, "wb") as f:
        f.write(protector.encrypt(real_key))

    print("✔️ Senha criada e chave protegida!")


def unlock_master_key():
    """Pede a senha e retorna o objeto Fernet real já desbloqueado."""
    password = input("Senha para desbloquear o banco: ").strip()

    try:
        with open(SALT_PATH, "rb") as f:
            salt = f.read()

        derived = derive_key_from_password(password, salt)
        protector = Fernet(derived)

        with open(KEY_ENC_PATH, "rb") as f:
            encrypted = f.read()

        real_key = protector.decrypt(encrypted)
        print("✔️ Chave desbloqueada com sucesso!")
        return Fernet(real_key)

    except Exception:
        print("❌ Senha incorreta. Encerrando.")
        sys.exit(1)


# ================================================================
# 🔐 Banco de dados criptografado
# ================================================================
def decrypt_db_to(path_plain=None):
    global FERNET_INSTANCE
    fernet = FERNET_INSTANCE

    if path_plain is None:
        fd, path_plain = tempfile.mkstemp(prefix="messages_", suffix=".db")
        os.close(fd)

    if os.path.exists(ENC_DB_PATH):
        with open(ENC_DB_PATH, 'rb') as f:
            encrypted = f.read()
        try:
            plaintext = fernet.decrypt(encrypted)
        except Exception as e:
            raise RuntimeError(f"Falha ao descriptografar o banco: {e}")

        with open(path_plain, 'wb') as f:
            f.write(plaintext)
    else:
        conn = sqlite3.connect(path_plain)
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            sender TEXT,
            receiver TEXT,
            content TEXT,
            group_name TEXT
        )
        """)
        conn.commit()
        conn.close()

    return path_plain


def encrypt_plain_db(path_plain):
    global FERNET_INSTANCE
    fernet = FERNET_INSTANCE

    with open(path_plain, 'rb') as f:
        data = f.read()

    token = fernet.encrypt(data)

    with open(ENC_DB_PATH, 'wb') as f:
        f.write(token)

    try:
        os.remove(path_plain)
    except:
        pass


def init_db():
    plain = decrypt_db_to()
    conn = sqlite3.connect(plain)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        sender TEXT,
        receiver TEXT,
        content TEXT,
        group_name TEXT
    )
    """)
    conn.commit()
    conn.close()
    encrypt_plain_db(plain)


def save_message(timestamp, sender, receiver, content, group_name=None):
    plain = decrypt_db_to()
    try:
        conn = sqlite3.connect(plain)
        c = conn.cursor()
        c.execute(
            "INSERT INTO messages (timestamp, sender, receiver, content, group_name) VALUES (?, ?, ?, ?, ?)",
            (timestamp, sender, receiver, content, group_name)
        )
        conn.commit()
    finally:
        conn.close()
        encrypt_plain_db(plain)


def fetch_history(limit=200):
    plain = decrypt_db_to()
    msgs = []
    try:
        conn = sqlite3.connect(plain)
        c = conn.cursor()
        c.execute(
            "SELECT timestamp, sender, receiver, content, group_name FROM messages ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        rows = c.fetchall()
        msgs = list(reversed(rows))
    finally:
        conn.close()
        encrypt_plain_db(plain)

    return msgs

USER_KEY_CACHE = {}

# ---------- Helpers para persistência de user_id e leitura de totp secret ----------
def get_userid_path_for(alias):
    return os.path.join(KEY_DIR, f"{alias}.id")

def persist_user_id(alias, uid):
    path = get_userid_path_for(alias)
    with open(path, "w", encoding="utf-8") as f:
        f.write(uid)

def load_persisted_user_id(alias):
    path = get_userid_path_for(alias)
    if os.path.exists(path):
        return open(path, "r", encoding="utf-8").read().strip()
    return None

def load_local_totp_secret(alias):
    """
    Lê o arquivo frontend/keys/<alias>.key e retorna o secret TOTP.
    Aceita texto puro ou JSON com {"totp_secret": "..."}.
    """
    key_path = os.path.join(KEY_DIR, f"{alias}.key")
    if not os.path.exists(key_path):
        print(f"[2FA] Nenhum arquivo de chave encontrado para {alias} em {KEY_DIR}")
        return None

    try:
        content = open(key_path, "r", encoding="utf-8").read().strip()
        # tentar JSON
        try:
            data = json.loads(content)
            return data.get("totp_secret") or data.get("secret")
        except:
            # não era JSON → assume secret puro
            return content
    except Exception as e:
        print("[2FA] Erro lendo secret local:", e)
        return None

# ------------------ SOCKET.IO EVENTS ------------------
@sio.event
def connect():
    print('[connected to server]')

@sio.on('register_response')
def on_register_response(data):
    global user_id, alias
    if data.get('error'):
        print('[register error]', data['error'])
        return

    print('[registered]', data)

    # update local alias/user_id if provided by server
    server_user_id = data.get('user_id')
    server_alias = data.get('alias') or alias

    if server_alias:
        alias = server_alias

    # if server returned user_id (new registration or reconnection), persist it locally
    if server_user_id:
        user_id = server_user_id
        try:
            persist_user_id(alias, user_id)
        except Exception as e:
            print("[WARN] falha ao persistir user_id:", e)

    # If the server provided totp_secret (first time registration), show it and optionally save
    if data.get('totp_secret'):
        print("[2FA] Novo TOTP secret recebido (salve no seu authenticator):", data['totp_secret'])
        # Optionally: you may want to save this secret to KEY_DIR/<alias>.key in JSON form
        # but we will not overwrite existing keys automatically.

    # If status ok, attempt auto 2FA login by reading local secret
    if data.get('status') == 'ok':
        print(f"[2FA] Tentando auto-login 2FA para {alias} (user {user_id[:8]})...")
        secret = load_local_totp_secret(alias)
        if not secret:
            print("[2FA] Nenhum secret local encontrado. Auto-login impossível.")
            return

        try:
            token = pyotp.TOTP(secret).now()
            print("[2FA] token gerado (auto):", token)
            # opcional: enviar token no register também (server aceita token opcional)
            sio.emit("login_2fa", {"user_id": user_id, "token": token})
            print("[2FA] login_2fa enviado automaticamente.")
        except Exception as e:
            print("[2FA] Erro gerando/enviando TOTP token:", e)

@sio.on('message')
def on_message(data):
    global USER_KEY_CACHE, priv
    try:
        sender_id = data.get('from')
        sender_alias = data.get('alias', sender_id[:8])
        signature = data.get('signature')

        # cipher pode ser string do numero grande (paillier)
        c_raw = data.get('cipher')
        if c_raw is None:
            print("[ERRO] Mensagem sem campo 'cipher'. Ignorando.")
            return

        c = int(c_raw)
        length = int(data.get('len', 0))
        dec = paillier_decrypt(priv, c)

        msg_bytes = dec.to_bytes(length, 'big')
        msg = msg_bytes.decode(errors='replace')

        # assinaturas (só para mensagens que não são SYSTEM)
        if sender_id and sender_id != 'SYSTEM':
            sender_pub = USER_KEY_CACHE.get(sender_id)
            if not sender_pub:
                users = requests.get(f"{API}/users").json().get('users', [])
                for u in users:
                    if u['user_id'] == sender_id:
                        pk = u['pub_key']
                        e_val = int(pk.get('e', 65537))
                        pub_obj = Pub(int(pk['n']), int(pk['g']), int(pk['n2']), e_val)
                        USER_KEY_CACHE[sender_id] = pub_obj
                        sender_pub = pub_obj
                        break

            if not sender_pub:
                print(f"[ERRO] Sem chave pública para {sender_alias}")
                return

            if not signature:
                print(f"[ALERTA] Mensagem sem assinatura — descartada")
                return

            if not paillier_verify(sender_pub, signature, msg_bytes):
                print(f"[ALERTA] Assinatura inválida! Mensagem descartada.")
                return

        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        if 'group' in data:
            print(f"\n[{now}] [{data['group']}] {sender_alias} > {msg}")
            save_message(now, sender_alias, None, msg, data.get('group'))
        else:
            print(f"\n[{now}] [{sender_alias}] > {msg}")
            save_message(now, sender_alias, data.get('to'), msg, None)

    except Exception as e:
        print(f"[ERRO AO PROCESSAR MENSAGEM] {e}")

@sio.on('send_response')
def on_send_response(data):
    if data.get('error'):
        print('[send error]', data['error'])

# ------------------ MAIN CLIENT LOGIC ------------------
def ensure_user_id_for_alias(chosen_alias):
    """
    Mantém user_id persistente por alias (arquivo keys/<alias>.id).
    Se existir, reutiliza. Se não, gera novo e persiste.
    """
    existing = load_persisted_user_id(chosen_alias)
    if existing:
        return existing
    new_id = str(uuid.uuid4())
    persist_user_id(chosen_alias, new_id)
    return new_id

def build_bundle_for_group(group, msg_bytes):
    """
    Monta o bundle { user_id: {"c": "<ciphertext>", "l": N}, ... }
    Requer que o servidor disponibilize /groups/<group>/members e /users.
    """
    # buscar membros do grupo
    resp = requests.get(f"{API}/groups/{group}/members")
    if resp.status_code != 200:
        raise RuntimeError("Failed to fetch group members: " + resp.text)
    members = resp.json().get('members', [])
    if not members:
        raise RuntimeError("Group has no members or does not exist")

    # buscar lista de users para mapear pubkeys
    users = requests.get(f"{API}/users").json().get('users', [])

    users_map = {u['user_id']: u for u in users}

    m_int = int.from_bytes(msg_bytes, 'big')
    bundle = {}
    for member in members:
        # pula o remetente
        if member == user_id:
            continue
        u = users_map.get(member)
        if not u:
            # se pubkey não encontrada, pula (cliente pode avisar)
            print(f"[WARN] pubkey não encontrada para membro {member[:8]}, pulando")
            continue
        pk = u['pub_key']
        pub_to = Pub(int(pk['n']), int(pk['g']), int(pk['n2']), int(pk.get('e', 65537)))
        cipher = paillier_encrypt(pub_to, m_int)
        bundle[member] = {"c": str(cipher), "l": len(msg_bytes)}
    return bundle

def main():
    global user_id, priv, pub, alias, USER_KEY_CACHE, FERNET_INSTANCE

    # Senha obrigatória antes de tudo (db criptografado)
    init_master_key()
    FERNET_INSTANCE = unlock_master_key()

    init_db()

    alias = input('Nome de usuário: ').strip()
    # persistir/reutilizar o user_id para o mesmo alias
    user_id = ensure_user_id_for_alias(alias)

    # gera chaves (ou, se você quiser, poderia carregar chaves existentes de KEY_DIR/<alias>.key)
    print(f'[{alias}] Gerando chaves Paillier (ou usando as existentes)...')
    pub, priv = paillier_keygen()

    pub_obj = {
        "n": str(pub.n),
        "g": str(pub.g),
        "n2": str(pub.n2),
        "e": str(pub.e)
    }

    sio.connect(WS, wait=True)

    # envia register. Note: pode incluir token opcional se quiser (não necessário, pois o cliente vai emitir login_2fa automaticamente ao receber response)
    sio.emit('register', {
        'user_id': user_id,
        'alias': alias,
        'pub_key': pub_obj
    })

    try:
        while True:
            cmd = input('> ').strip()

            if cmd == '/users':
                try:
                    res = requests.get(f"{API}/users").json()
                    print('Usuários no servidor:')
                    for u in res['users']:
                        print(f"  {u['alias']} ({u['user_id'][:8]})")
                except Exception as e:
                    print('(Erro ao consultar /users)', e)

            elif cmd == '/groups':
                try:
                    res = requests.get(f"{API}/groups").json()
                    print('Grupos disponíveis:')
                    for g in res['groups']:
                        print(f"  {g['name']} ({g['members']} membros) - {g.get('privacy', 'public')}")
                except Exception as e:
                    print('(Erro ao consultar /groups)', e)

            elif cmd.startswith('/create '):
                args = cmd[len('/create '):].strip()
                privacy = 'public'
                if args.lower().endswith(' private'):
                    privacy = 'private'
                    args = args[:-len(' private')].strip()
                group = args.strip()
                if not group:
                    print('Formato: /create nome_do_grupo [private]')
                    continue
                sio.emit('create_group', {'group': group, 'user_id': user_id, 'privacy': privacy})

            elif cmd.startswith('/join '):
                group = cmd.split(' ', 1)[1]
                sio.emit('join_group', {'group': group, 'user_id': user_id})

            elif cmd.startswith('/leave '):
                try:
                    group = cmd.split(' ', 1)[1].strip()
                except IndexError:
                    print('Formato: /leave nome_do_grupo')
                    continue
                if not group:
                    print('Formato: /leave nome_do_grupo')
                    continue
                sio.emit('leave_group', {'group': group, 'user_id': user_id})

            elif cmd.startswith('/invite '):
                args = cmd[len('/invite '):].strip()
                if ' ' not in args:
                    print('Formato: /invite nome_do_grupo nome_da_pessoa')
                    continue
                group, target_alias = args.rsplit(' ', 1)
                sio.emit('invite_user', {'group': group.strip(), 'from_id': user_id, 'target_alias': target_alias.strip()})

            elif cmd.startswith('@'):
                if ':' not in cmd[1:]:
                    print('Formato: @apelido:mensagem')
                    continue
                target_alias, msg = cmd[1:].split(':', 1)
                msg = msg.strip()

                users = requests.get(f"{API}/users").json()['users']
                target = next((u for u in users if u['alias'] == target_alias), None)
                if not target:
                    print('Usuário não encontrado.')
                    continue

                pk = target['pub_key']
                pub_to = Pub(int(pk['n']), int(pk['g']), int(pk['n2']), int(pk['e']))

                msg_bytes = msg.encode()
                m_int = int.from_bytes(msg_bytes, 'big')
                cipher = paillier_encrypt(pub_to, m_int)
                signature = paillier_sign(priv, msg_bytes)

                sio.emit('send', {
                    'from_id': user_id,
                    'to_id': target['user_id'],
                    'cipher': str(cipher),
                    'length': len(msg),
                    'signature': signature
                })

                now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                save_message(now, alias, target_alias, msg, None)
                print('[Mensagem enviada]')

            elif cmd.startswith('#'):
                if ':' not in cmd[1:]:
                    print('Formato: #grupo:mensagem')
                    continue
                group, msg = cmd[1:].split(':', 1)
                msg = msg.strip()

                msg_bytes = msg.encode()
                signature = paillier_sign(priv, msg_bytes)

                # Monta bundle com encryptions para cada membro (servidor tem rota /groups/<group>/members)
                try:
                    bundle = build_bundle_for_group(group, msg_bytes)
                except Exception as e:
                    print("[Erro ao montar bundle]", e)
                    continue

                # Envia UM ÚNICO send_group com bundle
                sio.emit('send_group', {
                    'group': group,
                    'from_id': user_id,
                    'bundle': bundle,
                    'signature': signature
                })

                now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                save_message(now, alias, f"grupo:{group}", msg, group)
                print(f"[Mensagem enviada para grupo {group}]")

            elif cmd == '/history':
                msgs = fetch_history(limit=500)
                if not msgs:
                    print('[Histórico vazio]')
                else:
                    print('\n--- Histórico de mensagens ---')
                    for ts, sender, receiver, content, group in msgs:
                        if group:
                            print(f"[{ts}] [grupo:{group}] {sender} -> {content}")
                        elif receiver:
                            print(f"[{ts}] {sender} -> {receiver}: {content}")
                        else:
                            print(f"[{ts}] {sender}: {content}")
                    print('--- Fim do histórico ---\n')

            elif cmd == '/quit':
                break

            else:
                print('Comandos: /users, /groups, /create grupo [private], /join grupo, /leave grupo, /invite grupo nome, @apelido:msg, #grupo:msg, /history, /quit')

    finally:
        sio.disconnect()

if __name__ == '__main__':
    main()
