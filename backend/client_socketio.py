# Updated client_socketio.py
# Adds encryption of the sqlite .db using cryptography.Fernet
# Adds a /history command to view saved messages (decrypts temporarily).

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
from cryptography.fernet import Fernet

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
KEY_DIR = "keys"
KEY_PATH = os.path.join(KEY_DIR, "fernet.key")

# ---------------------------------------------------------
# Fernet key helpers
# ---------------------------------------------------------

def ensure_key():
    os.makedirs(KEY_DIR, exist_ok=True)
    if not os.path.exists(KEY_PATH):
        key = Fernet.generate_key()
        with open(KEY_PATH, 'wb') as f:
            f.write(key)
        return key
    with open(KEY_PATH, 'rb') as f:
        return f.read()


def get_fernet():
    key = ensure_key()
    return Fernet(key)

# ---------------------------------------------------------
# Encrypted DB helpers
# Strategy:
# - The on-disk encrypted file is messages.db.enc
# - When we need to read/write we decrypt into a temporary file (in the system tempdir), operate, then re-encrypt to messages.db.enc
# - The plaintext messages.db is NEVER left on disk long-term; it is removed after use.
# ---------------------------------------------------------

def decrypt_db_to(path_plain=None):
    """Decrypt ENC_DB_PATH into a plaintext path and return that path.
    If ENC_DB_PATH does not exist, creates an empty DB at the plaintext path.
    Caller MUST remove the plaintext file when done.
    """
    fernet = get_fernet()
    if path_plain is None:
        fd, path_plain = tempfile.mkstemp(prefix="messages_", suffix=".db")
        os.close(fd)
    # If encrypted file exists, decrypt it
    if os.path.exists(ENC_DB_PATH):
        with open(ENC_DB_PATH, 'rb') as f:
            encrypted = f.read()
        try:
            plaintext = fernet.decrypt(encrypted)
        except Exception as e:
            # If decryption fails, raise so calling code can handle
            raise RuntimeError(f"Falha ao descriptografar o banco: {e}")
        with open(path_plain, 'wb') as f:
            f.write(plaintext)
    else:
        # Make sure an empty DB with the needed schema exists
        conn = sqlite3.connect(path_plain)
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                sender TEXT,
                receiver TEXT,
                content TEXT,
                group_name TEXT
            )
            """
        )
        conn.commit()
        conn.close()
    return path_plain


def encrypt_plain_db(path_plain):
    fernet = get_fernet()
    with open(path_plain, 'rb') as f:
        data = f.read()
    token = fernet.encrypt(data)
    with open(ENC_DB_PATH, 'wb') as f:
        f.write(token)
    try:
        os.remove(path_plain)
    except Exception:
        pass

# ---------------------------------------------------------
# SQLite helpers that operate via decrypt/edit/encrypt
# ---------------------------------------------------------

def init_db():
    # Ensure there's an encrypted DB; if not, create empty encrypted DB
    plain = decrypt_db_to()
    # ensure table exists
    conn = sqlite3.connect(plain)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            sender TEXT,
            receiver TEXT,
            content TEXT,
            group_name TEXT
        )
        """
    )
    conn.commit()
    conn.close()
    encrypt_plain_db(plain)


def save_message(timestamp, sender, receiver, content, group_name=None):
    # decrypt, insert, encrypt
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
        c.execute("SELECT timestamp, sender, receiver, content, group_name FROM messages ORDER BY id DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        # return in chronological order
        msgs = list(reversed(rows))
    finally:
        conn.close()
        encrypt_plain_db(plain)
    return msgs

# ---------------------------------------------------------
# The rest of the original client code (handlers, main loop)
# ---------------------------------------------------------

USER_KEY_CACHE = {}

@sio.event
def connect():
    print('[connected to server]')

@sio.on('register_response')
def on_register_response(data):
    if data.get('error'):
        print('[register error]', data['error'])
    else:
        print('[registered]', data)

# ---------------------------------------------------------
# RECEBIMENTO DE MENSAGENS + SALVAR NO SQLITE (AGORA CRIPTOGRAFADO)
# ---------------------------------------------------------
@sio.on('message')
def on_message(data):
    global USER_KEY_CACHE
    try:
        sender_id = data.get('from')
        sender_alias = data.get('alias', sender_id[:8])
        signature = data.get('signature')

        c = int(data.get('cipher'))
        length = int(data.get('len'))
        dec = paillier_decrypt(priv, c)

        msg_bytes = dec.to_bytes(length, 'big')
        msg = msg_bytes.decode(errors='replace')

        # Verificação de assinatura, exceto SYSTEM
        if sender_id != 'SYSTEM':
            sender_pub = USER_KEY_CACHE.get(sender_id)
            if not sender_pub:
                users = requests.get(f"{API}/users").json()['users']
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

            is_valid = paillier_verify(sender_pub, signature, msg_bytes)
            if not is_valid:
                print(f"[ALERTA] Assinatura inválida! Mensagem descartada.")
                return

        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        # Impressão
        if 'group' in data:
            print(f"\n[{now}] [{data['group']}] {sender_alias} > {msg}")
        else:
            print(f"\n[{now}] [{sender_alias}] > {msg}")

        # Salva mensagem recebida (criptografada no disco)
        save_message(now, sender_alias, None if 'group' in data else data.get('to'), msg, data.get('group'))

    except Exception as e:
        print(f"[ERRO AO PROCESSAR MENSAGEM] {e}")

# ---------------------------------------------------------

@sio.on('send_response')
def on_send_response(data):
    if data.get('error'):
        print('[send error]', data['error'])

# Demais handlers do arquivo original continuam sem alteração
# (grupos, convites, etc.)

# ---------------------------------------------------------

def main():
    global user_id, priv, pub, alias, USER_KEY_CACHE

    init_db()

    alias = input('Nome de usuário: ').strip()
    user_id = str(uuid.uuid4())

    print(f'[{alias}] Gerando chaves Paillier...')
    pub, priv = paillier_keygen()

    pub_obj = {"n": str(pub.n), "g": str(pub.g), "n2": str(pub.n2), "e": str(pub.e)}

    sio.connect(WS)

    sio.emit('register', {
        'user_id': user_id,
        'alias': alias,
        'pub_key': pub_obj
    })

    try:
        while True:
            cmd = input('> ').strip()

            # Mostrar usuários
            if cmd == '/users':
                try:
                    res = requests.get(f"{API}/users").json()
                    print('Usuários online:')
                    for u in res['users']:
                        print(f"  {u['alias']} ({u['user_id'][:8]})")
                except Exception as e:
                    print('(Erro ao consultar /users)', e)

            # Mostrar Grupos
            elif cmd == '/groups':
                try:
                    res = requests.get(f"{API}/groups").json()
                    print('Grupos disponíveis:')
                    for g in res['groups']:
                        print(f"  {g['name']} ({g['members']} membros) - {g.get('privacy', 'public')}")
                except Exception as e:
                    print('(Erro ao consultar /groups)', e)

            # Criar grupo
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

            # Entrar em grupo
            elif cmd.startswith('/join '):
                group = cmd.split(' ', 1)[1]
                sio.emit('join_group', {'group': group, 'user_id': user_id})
        

            # Sair do grupo
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

            # Convidar para grupo
            elif cmd.startswith('/invite '):
                args = cmd[len('/invite '):].strip()
                if ' ' not in args:
                    print('Formato: /invite nome_do_grupo nome_da_pessoa')
                    continue
                group, target_alias = args.rsplit(' ', 1)
                group = group.strip()
                target_alias = target_alias.strip()
                if not group or not target_alias:
                    print('Formato: /invite nome_do_grupo nome_da_pessoa')
                    continue
                sio.emit('invite_user', {'group': group, 'from_id': user_id, 'target_alias': target_alias})

            # Enviar mensagem privada
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

                # Salva mensagem enviada
                now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                save_message(now, alias, target_alias, msg, None)
                print('[Mensagem enviada]')

            elif cmd.startswith('#'):
                if ':' not in cmd[1:]:
                    print('Formato: #grupo:mensagem')
                    continue
                group, msg = cmd[1:].split(':', 1)
                msg = msg.strip()

                users = requests.get(f"{API}/users").json()['users']

                msg_bytes = msg.encode()
                m_int = int.from_bytes(msg_bytes, 'big')
                signature = paillier_sign(priv, msg_bytes)

                for u in users:
                    pk = u['pub_key']
                    pub_to = Pub(int(pk['n']), int(pk['g']), int(pk['n2']), int(pk.get('e', 65537)))
                    cipher = paillier_encrypt(pub_to, m_int)

                    sio.emit('send_group', {
                        'group': group,
                        'from_id': user_id,
                        'cipher': str(cipher),
                        'length': len(msg),
                        'signature': signature,
                        'to_id': u['user_id']
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
