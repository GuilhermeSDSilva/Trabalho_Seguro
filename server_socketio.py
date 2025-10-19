from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import threading
from paillier import Pub

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Armazenamento em memória
clients = {}      # user_id -> {alias, pub_key}
messages = {}     # user_id -> [ {from, cipher, len, group?} ]
user_sid = {}     # user_id -> sid
sid_user = {}     # sid -> user_id
groups = {}       # group_name -> set(user_id)
lock = threading.Lock()

@app.route("/users", methods=["GET"])
def list_users():
    with lock:
        user_list = [
            {"user_id": uid, "alias": info["alias"], "pub_key": info["pub_key"]}
            for uid, info in clients.items()
        ]
    return jsonify({"users": user_list})

# ---------------- REGISTRO ----------------
@socketio.on('register')
def handle_register(data):
    """Data esperado: { user_id, alias, pub_key }"""
    user_id = data.get('user_id')
    alias = data.get('alias')
    pub_key = data.get('pub_key')
    sid = request.sid

    if not user_id or not alias or not pub_key:
        emit('register_response', {'error': 'Missing fields'})
        return

    with lock:
        if user_id in clients:
            user_sid[user_id] = sid
            sid_user[sid] = user_id
            emit('register_response', {'status': 'ok', 'note': 'reconnected'})
            return
        clients[user_id] = {'alias': alias, 'pub_key': pub_key}
        messages.setdefault(user_id, [])
        user_sid[user_id] = sid
        sid_user[sid] = user_id

    print(f"[+] {alias} registrado ({user_id[:8]})  sid={sid}")
    emit('register_response', {'status': 'ok', 'user_id': user_id})

    # Enviar mensagens pendentes, se houver
    with lock:
        pending = messages.get(user_id, [])[:]
        messages[user_id] = []

    for m in pending:
        emit('message', m)

# ---------------- MENSAGEM DIRETA ----------------
@socketio.on('send')
def handle_send(data):
    """Data esperado: { from_id, to_id, cipher, length }"""
    from_id = data.get('from_id')
    to_id = data.get('to_id')
    cipher = data.get('cipher')
    length = data.get('length')

    if not all([from_id, to_id, cipher, length]):
        emit('send_response', {'error': 'Missing fields'})
        return

    with lock:
        if to_id not in clients:
            emit('send_response', {'error': 'User not found'})
            return
        alias = clients.get(from_id, {}).get('alias', from_id[:8])
        msg = {'from': from_id, 'alias': alias, 'cipher': cipher, 'len': length}

        sid = user_sid.get(to_id)
        if sid:
            socketio.emit('message', msg, room=sid)
            print(f"[msg] {from_id[:8]} → {to_id[:8]} (delivered live)")
        else:
            messages.setdefault(to_id, []).append(msg)
            print(f"[msg] {from_id[:8]} → {to_id[:8]} (queued)")

    emit('send_response', {'status': 'sent'})

# ---------------- GRUPOS ----------------
@socketio.on('create_group')
def handle_create_group(data):
    """Data esperado: { 'group': nome_grupo, 'user_id': criador }"""
    group = data.get('group')
    uid = data.get('user_id')

    if not group or not uid:
        emit('create_group_response', {'error': 'Missing fields'})
        return

    with lock:
        if group in groups:
            emit('create_group_response', {'error': 'Group already exists'})
            return
        groups[group] = {uid}

    print(f"[+] Grupo criado: {group} por {uid[:8]}")
    emit('create_group_response', {'status': 'ok', 'group': group})


@socketio.on('join_group')
def handle_join_group(data):
    """Data esperado: { 'group': nome_grupo, 'user_id': usuario }"""
    group = data.get('group')
    uid = data.get('user_id')

    if not group or not uid:
        emit('join_group_response', {'error': 'Missing fields'})
        return

    with lock:
        if group not in groups:
            emit('join_group_response', {'error': 'Group not found'})
            return
        groups[group].add(uid)

    print(f"[+] {uid[:8]} entrou no grupo {group}")
    emit('join_group_response', {'status': 'ok', 'group': group})


@socketio.on('send_group')
def handle_send_group(data):
    """Data esperado: { 'from_id', 'group', 'cipher', 'length' }"""
    from_id = data.get('from_id')
    group = data.get('group')
    cipher = data.get('cipher')
    length = data.get('length')

    if not all([from_id, group, cipher, length]):
        emit('send_response', {'error': 'Missing fields'})
        return

    with lock:
        if group not in groups:
            emit('send_response', {'error': 'Group not found'})
            return
        members = groups[group].copy()

    alias = clients.get(from_id, {}).get('alias', from_id[:8])
    msg = {'from': from_id, 'alias': alias, 'cipher': cipher, 'len': length, 'group': group}

    for member in members:
        if member == from_id:
            continue
        sid = user_sid.get(member)
        if sid:
            socketio.emit('message', msg, room=sid)
        else:
            messages.setdefault(member, []).append(msg)

    print(f"[group:{group}] {from_id[:8]} → {len(members)-1} membros")
    emit('send_response', {'status': 'sent', 'group': group})

# ---------------- DESCONECTAR ----------------
@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    with lock:
        uid = sid_user.pop(sid, None)
        if uid:
            user_sid.pop(uid, None)
            print(f"[-] {uid[:8]} disconnected (sid={sid})")

if __name__ == '__main__':
    print('Starting Socket.IO server on :5000')
    socketio.run(app, host='0.0.0.0', port=5000)
