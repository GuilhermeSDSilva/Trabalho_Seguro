import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import threading
from paillier import Pub, paillier_encrypt



app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Armazenamento em memória
clients = {}      # user_id -> {alias, pub_key}
messages = {}     # user_id -> [ {from, cipher, len, group?} ]
user_sid = {}     # user_id -> sid
sid_user = {}     # sid -> user_id
groups = {}       # group_name -> set(user_id)
group_privacy = {}   # group_name -> 'public' ou 'private'
group_invites = {}   # group_name -> set(user_id)
lock = threading.Lock()

@app.route("/users", methods=["GET"])
def list_users():
    with lock:
        user_list = [
            {"user_id": uid, "alias": info["alias"], "pub_key": info["pub_key"]}
            for uid, info in clients.items()
        ]
    return jsonify({"users": user_list})

@app.route("/groups", methods=["GET"])
def list_groups():
    """Retorna uma lista de grupos e o número de membros."""
    with lock:
        group_list = [
            {"name": name, "members": len(members), "privacy": group_privacy.get(name, "public")}
            for name, members in groups.items()
        ]
    return jsonify({"groups": group_list})

# ---------------- REGISTRO (COM CORREÇÃO) ----------------
@socketio.on('register')
def handle_register(data):
    """Data esperado: { user_id, alias, pub_key: {n, g, n2, e} }"""
    user_id = data.get('user_id')
    alias = data.get('alias')
    pub_key = data.get('pub_key')
    sid = request.sid

    if not user_id or not alias or not pub_key:
        emit('register_response', {'error': 'Missing fields'})
        return

    with lock:
        # 1. Verifica se o user_id já existe (reconexão)
        if user_id in clients:
            user_sid[user_id] = sid
            sid_user[sid] = user_id
            
            clients[user_id]['pub_key'] = pub_key 
            
            emit('register_response', {'status': 'ok', 'note': 'reconnected'})
            return
            
        # --- INÍCIO DA MODIFICAÇÃO ---
        # 2. Verifica se o ALIAS já está em uso por OUTRO user_id
        for uid, info in clients.items():
            if info.get('alias') == alias:
                # Se o alias já existe, rejeita o registro
                emit('register_response', {'error': 'Este nome de usuário já está em uso.'})
                return
        # --- FIM DA MODIFICAÇÃO ---
            
        # 3. Se for totalmente novo, registra
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
    """Data esperado: { from_id, to_id, cipher, length, signature }"""
    from_id = data.get('from_id')
    to_id = data.get('to_id')
    cipher = data.get('cipher')
    length = data.get('length')
    signature = data.get('signature')

    if not all([from_id, to_id, cipher, length, signature]):
        emit('send_response', {'error': 'Missing fields'})
        return

    with lock:
        if to_id not in clients:
            emit('send_response', {'error': 'User not found'})
            return
        alias = clients.get(from_id, {}).get('alias', from_id[:8])
        msg = {'from': from_id, 'alias': alias, 'cipher': cipher, 'len': length, 'signature': signature} 

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
    """Data esperado: { 'group': nome_grupo, 'user_id': criador, 'privacy': opcional }"""
    group = data.get('group')
    uid = data.get('user_id')
    privacy = data.get('privacy', 'public')

    if not group or not uid:
        emit('create_group_response', {'error': 'Missing fields'})
        return

    with lock:
        if group in groups:
            emit('create_group_response', {'error': 'Group already exists'})
            return
        groups[group] = {uid}
        group_privacy[group] = privacy
        group_invites[group] = set()

    print(f"[+] Grupo criado: {group} ({privacy}) por {uid[:8]}")
    emit('create_group_response', {'status': 'ok', 'group': group, 'privacy': privacy})


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
        
        # Verificar se o grupo é privado
        if group_privacy.get(group, 'public') == 'private':
            allowed = uid in group_invites.get(group, set()) or uid in groups[group]
            if not allowed:
                emit('join_group_response', {'error': 'Private group — invite required'})
                return
        
        if uid in groups[group]:
            emit('join_group_response', {'status': 'ok', 'group': group, 'note': 'already member'})
            return
            
        groups[group].add(uid)
        alias = clients.get(uid, {}).get('alias', uid[:8])
        
    print(f"[+] {uid[:8]} entrou no grupo {group}")
    emit('join_group_response', {'status': 'ok', 'group': group})
    _send_system_message_to_group(group, f"{alias} entrou no grupo.")


@socketio.on('invite_user')
def handle_invite_user(data):
    """Data esperado: { 'group': nome_grupo, 'from_id': quem convida, 'target_alias': nome do convidado }"""
    group = data.get('group')
    inviter = data.get('from_id')
    target_alias = data.get('target_alias')

    if not all([group, inviter, target_alias]):
        emit('invite_response', {'error': 'Missing fields'})
        return

    with lock:
        if group not in groups:
            emit('invite_response', {'error': 'Group not found'})
            return

        if group_privacy.get(group, 'public') != 'private':
            emit('invite_response', {'error': 'Group is not private'})
            return

        target_id = None
        for uid, info in clients.items():
            if info.get('alias') == target_alias:
                target_id = uid
                break

        if not target_id:
            emit('invite_response', {'error': 'User not found'})
            return

        group_invites[group].add(target_id)

    print(f"[INVITE] {inviter[:8]} convidou {target_alias} para o grupo {group}")
    emit('invite_response', {'status': 'ok', 'group': group, 'invited': target_alias})


@socketio.on('send_group')
def handle_send_group(data):
    """Data esperado: { 'from_id', 'group', 'cipher', 'length', 'signature', 'to_id' }"""
    from_id = data.get('from_id')
    group = data.get('group')
    cipher = data.get('cipher')
    length = data.get('length')
    signature = data.get('signature')
    to_id = data.get('to_id')

    if not all([from_id, group, cipher, length, signature, to_id]):
        emit('send_response', {'error': 'Missing fields'})
        return

    with lock:
        if group not in groups:
            emit('send_response', {'error': 'Group not found'})
            return
        
        if from_id not in groups[group]:
             emit('send_response', {'error': 'Sender not in group'})
             return
             
        if to_id not in groups[group]:
            return 
            
        alias = clients.get(from_id, {}).get('alias', from_id[:8])
        msg = {'from': from_id, 'alias': alias, 'cipher': cipher, 'len': length, 'group': group, 'signature': signature}
        sid = user_sid.get(to_id)

        if sid:
            socketio.emit('message', msg, room=sid)
            print(f"[group:E2EE:{group}] {from_id[:8]} → {to_id[:8]} (delivered live)")
        else:
            messages.setdefault(to_id, []).append(msg)
            print(f"[group:E2EE:{group}] {from_id[:8]} → {to_id[:8]} (queued)")

    emit('send_response', {'status': 'sent', 'group': group}) 

def _send_system_message_to_group(group_name, message):
    with lock:
        if group_name not in groups:
            return
        
        members = groups[group_name].copy()
        
        member_keys = {}
        for uid in members:
            if uid in clients and 'pub_key' in clients[uid]:
                pk = clients[uid]['pub_key']
                # *** Nota: O paillier.py original não tinha 'e' no Pub. A versão mais nova tem.
                # Esta função (original) pode falhar se o paillier.py for antigo.
                # Assumindo o paillier.py mais recente que o app.py usa (com 'e')
                e_val = int(pk.get('e', 65537)) # Pega o 'e' da pub_key
                pub_obj = Pub(int(pk['n']), int(pk['g']), int(pk['n2']), e_val) 
                member_keys[uid] = pub_obj

    m_int = int.from_bytes(message.encode(), 'big')
    msg_len = len(message)
    
    for member_id, pub_key_obj in member_keys.items():
        try:
            # paillier_encrypt do servidor precisa da chave pública correta
            cipher = paillier_encrypt(pub_key_obj, m_int) 
            
            msg = {
                'from': 'SYSTEM',
                'alias': 'System',
                'cipher': str(cipher),
                'len': msg_len,
                'group': group_name
            }
            
            sid = user_sid.get(member_id)
            if sid:
                socketio.emit('message', msg, room=sid)
        except Exception as e:
            # Corrige a falha se o _send_system_message_to_group não tiver a biblioteca paillier.py
            # ou se a chave pública for do formato antigo.
            print(f"[ERROR] Falha ao criptografar/enviar mensagem do sistema para {member_id[:8]}: {e}")

    print(f"[system:{group_name}] Mensagem de sistema (tentativa) enviada: {message}")

# Evento para sair do grupo
@socketio.on('leave_group')
def handle_leave_group(data):
    """Data esperado: { 'group': nome_grupo, 'user_id': usuario }"""
    group = data.get('group')
    uid = data.get('user_id')

    if not group or not uid:
        emit('leave_group_response', {'error': 'Missing fields'})
        return

    with lock:
        if group not in groups:
            emit('leave_group_response', {'error': 'Group not found'})
            return
        
        alias = clients.get(uid, {}).get('alias', uid[:8])
        
        if uid in groups[group]:
            groups[group].remove(uid)
            is_deleted = False
            if not groups[group]:
                del groups[group]
                # Limpa também a privacidade e convites
                group_privacy.pop(group, None)
                group_invites.pop(group, None)
                is_deleted = True
                print(f"[-] Grupo removido: {group} (vazio)")
                
        else:
            emit('leave_group_response', {'error': 'Not a member'})
            return

    print(f"[-] {uid[:8]} saiu do grupo {group}")
    emit('leave_group_response', {'status': 'ok', 'group': group})
    
    if not is_deleted:
        _send_system_message_to_group(group, f"{alias} saiu do grupo.")

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