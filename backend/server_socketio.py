import sys
import os
import sqlite3
import json
import time
import threading
import pyotp
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit

# opcional: caminho do seu projeto
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

DB_FILE = "chat_seguro.db"
lock = threading.Lock()

# --- Em memória apenas para sessão (sids) ---
user_sid = {}     # user_id -> sid
sid_user = {}     # sid -> user_id

# --- BANCO DE DADOS: inicialização e helpers ---
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                alias TEXT UNIQUE,
                pub_key TEXT,
                totp_secret TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_id TEXT,
                to_id TEXT,
                group_id TEXT,
                content_blob TEXT,
                signature TEXT,
                timestamp REAL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                name TEXT PRIMARY KEY,
                owner_id TEXT,
                privacy TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                group_name TEXT,
                user_id TEXT,
                PRIMARY KEY (group_name, user_id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS group_invites (
                group_name TEXT,
                user_id TEXT,
                PRIMARY KEY (group_name, user_id)
            )
        ''')
        conn.commit()

init_db()

# --- Funções utilitárias de DB ---
def db_get_user_by_alias(alias):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM users WHERE alias = ?", (alias,)).fetchone()

def db_get_user_by_id(uid):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM users WHERE user_id = ?", (uid,)).fetchone()

def db_add_user(user_id, alias, pub_key, totp_secret):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO users (user_id, alias, pub_key, totp_secret) VALUES (?, ?, ?, ?)",
                     (user_id, alias, json.dumps(pub_key), totp_secret))
        conn.commit()

def db_update_pubkey(user_id, pub_key):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("UPDATE users SET pub_key = ? WHERE user_id = ?", (json.dumps(pub_key), user_id))
        conn.commit()

def db_insert_message(from_id, to_id, group_id, content_blob, signature):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO messages (from_id, to_id, group_id, content_blob, signature, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                     (from_id, to_id, group_id, json.dumps(content_blob), signature, time.time()))
        conn.commit()

def db_get_pending_for_user(uid):
    """
    Retorna listas de mensagens diretas e mensagens de grupo onde exista um pacote
    destinado a uid (quando group_id is not null)
    """
    result = []
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        # mensagens diretas
        rows = conn.execute("SELECT * FROM messages WHERE to_id = ? ORDER BY timestamp ASC", (uid,)).fetchall()
        for r in rows:
            item = dict(r)
            try: item['content_blob'] = json.loads(r['content_blob'])
            except: pass
            result.append(item)
        # mensagens em grupo: pega todas e filtra se o bundle contém uid
        rows = conn.execute("SELECT * FROM messages WHERE group_id IS NOT NULL ORDER BY timestamp ASC").fetchall()
        for r in rows:
            try:
                blob = json.loads(r['content_blob'])
                # blob tem formato { "<user_id>": {"c": "...", "l": N}, ... }
                if uid in blob:
                    item = dict(r)
                    item['content_blob'] = blob
                    result.append(item)
            except:
                continue
    return result

def db_get_groups():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM groups").fetchall()

def db_get_group_members(group_name):
    with sqlite3.connect(DB_FILE) as conn:
        return [row[0] for row in conn.execute("SELECT user_id FROM group_members WHERE group_name=?", (group_name,)).fetchall()]

# --- ROTAS HTTP: exposição (users/groups/debug) ---
@app.route("/users", methods=["GET"])
def list_users():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        users = conn.execute("SELECT user_id, alias, pub_key FROM users").fetchall()
        result = []
        for u in users:
            d = dict(u)
            try: d['pub_key'] = json.loads(u['pub_key'])
            except: pass
            result.append(d)
    return jsonify({"users": result})

@app.route("/groups", methods=["GET"])
def list_groups():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        groups_db = conn.execute("SELECT * FROM groups").fetchall()
        result = []
        for g in groups_db:
            gd = dict(g)
            members = db_get_group_members(g['name'])
            gd['members'] = len(members)
            result.append(gd)
    return jsonify({"groups": result})

@app.route("/groups/<group_name>/members", methods=["GET"])
def get_group_members_route(group_name):
    """
    Retorna os user_ids membros do grupo.
    Usado pelo cliente para montar o bundle de grupo.
    """
    members = db_get_group_members(group_name)
    return jsonify({"members": members})

@app.route("/debug/inspector", methods=["GET"])
def inspector():
    """
    Rota de auditoria: expõe todo o estado salvo no DB (usuarios, mensagens, grupos).
    ATENÇÃO: contém chaves públicas e secrets TOTP.
    Link para fazer inspeção: http://192.168.0.9:5000/debug/inspector
    """
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        users_db = conn.execute("SELECT * FROM users").fetchall()
        users_list = []
        for u in users_db:
            u_dict = dict(u)
            try: u_dict['pub_key'] = json.loads(u['pub_key'])
            except: pass
            users_list.append(u_dict)

        msgs_db = conn.execute("SELECT * FROM messages").fetchall()
        msgs_list = []
        for m in msgs_db:
            md = dict(m)
            try: md['content_blob'] = json.loads(m['content_blob'])
            except: pass
            msgs_list.append(md)

        groups_list = [dict(g) for g in conn.execute("SELECT * FROM groups").fetchall()]
        # adicionar membros e invites
        for g in groups_list:
            g['members'] = db_get_group_members(g['name'])
            invites = conn.execute("SELECT user_id FROM group_invites WHERE group_name=?", (g['name'],)).fetchall()
            g['invites'] = [i[0] for i in invites]

    return jsonify({
        "SERVER_STATUS": "ONLINE (Modo Auditoria)",
        "AUDITORIA_TOTAL": {
            "TOTAL_USUARIOS": len(users_list),
            "LISTA_USUARIOS": users_list,
            "TOTAL_MENSAGENS": len(msgs_list),
            "HISTORICO_MENSAGENS": msgs_list,
            "GRUPOS": groups_list
        }
    })

# --- SOCKET.IO: registro, login 2FA, envio e entrega de mensagens ---
@socketio.on('register')
def handle_register(data):
    """
    Esperado: { user_id, alias, pub_key }
    Se novo: cria entrada em users com totp_secret e retorna totp_secret (para ser exibido como QR/TXT no client)
    Se alias existente por outro user -> erro
    Se user_id já existe -> reconexão (atualiza sid e pub_key)
    Opcional: o cliente pode enviar 'token' no register para auto-login 2FA em reconexão.
    """
    user_id = data.get('user_id')
    alias = data.get('alias')
    pub_key = data.get('pub_key')
    sid = request.sid

    if not user_id or not alias or not pub_key:
        emit('register_response', {'error': 'Missing fields'})
        return

    with lock:
        existing_by_id = db_get_user_by_id(user_id)
        existing_by_alias = db_get_user_by_alias(alias)

        # Reconexão (mesmo user_id)
        if existing_by_id:
            user_sid[user_id] = sid
            sid_user[sid] = user_id
            db_update_pubkey(user_id, pub_key)
            emit('register_response', {'status': 'ok', 'note': 'reconnected', 'user_id': user_id, 'alias': existing_by_id['alias']})

            # Se o cliente forneceu token opcional aqui, tente autenticar e entregar
            token = data.get('token')
            if token:
                try:
                    secret = existing_by_id['totp_secret']
                    if pyotp.TOTP(secret).verify(token):
                        with lock:
                            user_sid[user_id] = sid
                            sid_user[sid] = user_id
                        deliver_pending(user_id, sid)
                        print(f"[2FA-auto] delivered pending on reconnection for {user_id[:8]}")
                    else:
                        print(f"[2FA-auto] invalid token provided on reconnection for {user_id[:8]}")
                except Exception as e:
                    print("Error verifying optional token on register:", e)
            return

        # se alias em uso por OUTRO user -> rejeitar
        if existing_by_alias:
            emit('register_response', {'error': 'Alias already in use'})
            return

        # criar novo user com TOTP
        totp = pyotp.random_base32()
        db_add_user(user_id, alias, pub_key, totp)

        # inserir sessão
        user_sid[user_id] = sid
        sid_user[sid] = user_id

    emit('register_response', {'status': 'ok', 'user_id': user_id, 'totp_secret': totp, 'alias': alias})
    print(f"[+] {alias} registered ({user_id[:8]}) sid={sid}")

@socketio.on('login_2fa')
def handle_login_2fa(data):
    """
    Espera: { user_id, token }
    Se token válido: marca como online (sid já deverá ter sido atribuído em register) e entrega pendentes
    """
    uid = data.get('user_id')
    token = data.get('token')
    sid = request.sid

    user = db_get_user_by_id(uid)
    if not user:
        emit('auth_fail', {'msg': 'User not found'})
        return

    secret = user['totp_secret']
    if pyotp.TOTP(secret).verify(token):
        with lock:
            user_sid[uid] = sid
            sid_user[sid] = uid
        emit('login_success', {'alias': user['alias']})
        # entregar pendentes
        deliver_pending(uid, sid)
    else:
        emit('auth_fail', {'msg': 'Invalid token'})

def deliver_pending(uid, sid):
    """
    Busca mensagens diretas e bundle de grupos que contenham uid e envia ao sid.
    Depois de entregues, as mensagens diretas são removidas; mensagens de grupo são mantidas (auditável).
    """
    pend = db_get_pending_for_user(uid)
    for m in pend:
        try:
            blob = m['content_blob']
            if m['group_id']:
                # bundle: extrai só o pacote do uid
                pkt = blob.get(uid)
                if not pkt:
                    continue
                payload = {
                    'from': m['from_id'],
                    'group': m['group_id'],
                    'cipher': pkt.get('c'),
                    'len': pkt.get('l'),
                    'signature': m.get('signature')
                }
            else:
                # mensagem direta
                payload = {
                    'from': m['from_id'],
                    'cipher': blob.get('c') if isinstance(blob, dict) else None,
                    'len': blob.get('l') if isinstance(blob, dict) else None,
                    'signature': m.get('signature')
                }
            # Corrigir um erro para quando um usuário recebe as mensagens offline antes dele conseguir logar
            socketio.sleep(100)

            socketio.emit('message', payload, room=sid)
        except Exception as e:
            print(f"[ERROR] delivering pending to {uid[:8]}: {e}")

    # Apaga mensagens diretas entregues (as de group_id serão mantidas para auditoria/histórico)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM messages WHERE to_id = ?", (uid,))
        conn.commit()

@socketio.on('send')  # mensagem direta
def handle_send(data):
    """
    Esperado: { from_id, to_id, cipher, length, signature }
    Salva em messages.to_id e tenta entregar se online.
    """
    from_id = data.get('from_id')
    to_id = data.get('to_id')
    cipher = data.get('cipher')
    length = data.get('length')
    signature = data.get('signature')

    if not all([from_id, to_id, cipher, length, signature]):
        emit('send_response', {'error': 'Missing fields'})
        return

    blob = {'c': cipher, 'l': length}
    db_insert_message(from_id, to_id, None, blob, signature)

    sid = user_sid.get(to_id)
    if sid:
        socketio.emit('message', {'from': from_id, 'cipher': cipher, 'len': length, 'signature': signature}, room=sid)
        print(f"[msg] {from_id[:8]} → {to_id[:8]} (delivered live)")
    else:
        print(f"[msg] {from_id[:8]} → {to_id[:8]} (queued)")

    emit('send_response', {'status': 'sent'})

@socketio.on('send_group')
def handle_send_group(data):
    """
    Esperado: {'from_id','group','bundle', 'signature'}
    bundle == { user_id: {'c': '<ciphertext>', 'l': N}, ... }
    -> salva UM ÚNICO registro com group_id preenchido (persistência de sessão/bundle).
    -> tenta enviar para membros online extraindo apenas o pacote de cada membro.
    """
    from_id = data.get('from_id')
    group = data.get('group')
    bundle = data.get('bundle')   # dict
    signature = data.get('signature')

    if not all([from_id, group, bundle, signature]):
        emit('send_response', {'error': 'Missing fields'})
        return

    # verificar existência do grupo e membros
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        grp = conn.execute("SELECT * FROM groups WHERE name = ?", (group,)).fetchone()
        if not grp:
            emit('send_response', {'error': 'Group not found'})
            return
        members = [row[0] for row in conn.execute("SELECT user_id FROM group_members WHERE group_name=?", (group,)).fetchall()]

    # salva bundle como um único registro
    db_insert_message(from_id, None, group, bundle, signature)
    print(f"[group] bundle saved for group {group} by {from_id[:8]}")

    # entrega a cada membro online (extraíndo somente o pacote destinado)
    for member in members:
        if member == from_id:
            continue
        pkt = bundle.get(member)
        if not pkt:
            continue
        sid = user_sid.get(member)
        if sid:
            msg = {'from': from_id, 'alias': None, 'cipher': pkt.get('c'), 'len': pkt.get('l'), 'group': group, 'signature': signature}
            socketio.emit('message', msg, room=sid)
            print(f"[group:E2EE:{group}] {from_id[:8]} → {member[:8]} (delivered live)")

    emit('send_response', {'status': 'sent', 'group': group})

# --- Gerenciamento de grupos (persistente) ---
@socketio.on('create_group')
def create_group(data):
    group = data.get('group')
    uid = data.get('user_id')
    privacy = data.get('privacy', 'public')

    if not group or not uid:
        emit('create_group_response', {'error': 'Missing fields'})
        return

    with sqlite3.connect(DB_FILE) as conn:
        try:
            conn.execute("INSERT INTO groups (name, owner_id, privacy) VALUES (?, ?, ?)", (group, uid, privacy))
            conn.execute("INSERT INTO group_members (group_name, user_id) VALUES (?, ?)", (group, uid))
            conn.commit()
            emit('create_group_response', {'status': 'ok', 'group': group, 'privacy': privacy})
            print(f"[+] Grupo criado: {group} ({privacy}) por {uid[:8]}")
        except sqlite3.IntegrityError:
            emit('create_group_response', {'error': 'Group exists'})

@socketio.on('join_group')
def join_group(data):
    group = data.get('group')
    uid = data.get('user_id')

    if not group or not uid:
        emit('join_group_response', {'error': 'Missing fields'})
        return

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        
        # Verifica se grupo existe e privacidade
        g = conn.execute("SELECT privacy FROM groups WHERE name=?", (group,)).fetchone()
        if not g:
            emit('join_group_response', {'error': 'Não existe'})
            return
        
        if g['privacy'] == 'private':
            if not conn.execute("SELECT 1 FROM group_invites WHERE group_name=? AND user_id=?", (group, uid)).fetchone():
                emit('join_group_response', {'error': 'Precisa de convite'})
                return
            conn.execute("DELETE FROM group_invites WHERE group_name=? AND user_id=?", (group, uid))
        
        try:
            # Adiciona o membro
            conn.execute("INSERT INTO group_members (group_name, user_id) VALUES (?, ?)", (group, uid))
            conn.commit()
            
            # Resposta para quem entrou
            emit('join_group_response', {'status': 'ok', 'group': group})
            print(f"[+] {uid[:8]} entrou no grupo {group}")

            # --- NOTIFICAÇÃO PARA OS OUTROS MEMBROS ---
            # 1. Pega o apelido de quem entrou
            user_row = conn.execute("SELECT alias FROM users WHERE user_id=?", (uid,)).fetchone()
            alias = user_row['alias'] if user_row else "Alguém"

            # 2. Pega todos os membros atuais do grupo
            members = [row[0] for row in conn.execute("SELECT user_id FROM group_members WHERE group_name=?", (group,)).fetchall()]
            
            # 3. Envia aviso para cada membro (exceto o próprio usuário)
            for m_id in members:
                if m_id == uid: continue
                
                target_sid = user_sid.get(m_id)
                if target_sid:
                    socketio.emit('message', {
                        'from': 'SYSTEM',
                        'group': group,
                        'content': f"O usuário {alias} entrou no grupo."
                    }, room=target_sid)
            # -------------------------------------------

        except sqlite3.IntegrityError:
            emit('join_group_response', {'status': 'ok', 'group': group, 'note': 'already member'})

@socketio.on('invite_user')
def invite_user(data):
    group = data.get('group')
    inviter = data.get('from_id')
    target_alias = data.get('target_alias')

    if not all([group, inviter, target_alias]):
        emit('invite_response', {'error': 'Missing fields'})
        return

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        g = conn.execute("SELECT * FROM groups WHERE name=?", (group,)).fetchone()
        if not g:
            emit('invite_response', {'error': 'Group not found'})
            return
        if g['privacy'] != 'private':
            emit('invite_response', {'error': 'Group is not private'})
            return
        tgt = conn.execute("SELECT user_id FROM users WHERE alias=?", (target_alias,)).fetchone()
        if not tgt:
            emit('invite_response', {'error': 'User not found'})
            return
        conn.execute("INSERT OR IGNORE INTO group_invites (group_name, user_id) VALUES (?, ?)", (group, tgt['user_id']))
        conn.commit()
    emit('invite_response', {'status': 'ok', 'group': group, 'invited': target_alias})
    print(f"[INVITE] {inviter[:8]} invited {target_alias} to {group}")

@socketio.on('leave_group')
def leave_group(data):
    group = data.get('group')
    uid = data.get('user_id')

    if not group or not uid:
        emit('leave_group_response', {'error': 'Missing fields'})
        return

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        
        # Verifica membro
        members_check = [r[0] for r in conn.execute("SELECT user_id FROM group_members WHERE group_name=?", (group,)).fetchall()]
        if uid not in members_check:
            emit('leave_group_response', {'error': 'Not a member'})
            return
        
        # Pega o alias antes de remover
        user_row = conn.execute("SELECT alias FROM users WHERE user_id=?", (uid,)).fetchone()
        alias = user_row['alias'] if user_row else "Alguém"

        # Remove do banco
        conn.execute("DELETE FROM group_members WHERE group_name=? AND user_id=?", (group, uid))
        conn.commit()

        # Verifica se o grupo ficou vazio
        rem = conn.execute("SELECT 1 FROM group_members WHERE group_name=?", (group,)).fetchone()
        
        if not rem:
            conn.execute("DELETE FROM groups WHERE name=?", (group,))
            conn.execute("DELETE FROM group_invites WHERE group_name=?", (group,))
            conn.commit()
            print(f"[-] Grupo removido: {group} (vazio)")
        else:
            # --- NOTIFICAÇÃO PARA QUEM FICOU ---
            # Pega lista atualizada de membros remanescentes
            remaining_members = [row[0] for row in conn.execute("SELECT user_id FROM group_members WHERE group_name=?", (group,)).fetchall()]
            
            for m_id in remaining_members:
                target_sid = user_sid.get(m_id)
                if target_sid:
                    socketio.emit('message', {
                        'from': 'SYSTEM',
                        'group': group,
                        'content': f"O usuário {alias} saiu do grupo."
                    }, room=target_sid)
            # -----------------------------------

    emit('leave_group_response', {'status': 'ok', 'group': group})
    print(f"[-] {uid[:8]} saiu do grupo {group}")

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    with lock:
        uid = sid_user.pop(sid, None)
        if uid:
            user_sid.pop(uid, None)
            print(f"[-] {uid[:8]} disconnected (sid={sid})")

if __name__ == '__main__':
    print('Starting secure messaging server on :5000')
    socketio.run(app, host='0.0.0.0', port=5000)
