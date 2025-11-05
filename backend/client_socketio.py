import socketio
import requests
import uuid
import threading
import time
import datetime
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from paillier import paillier_keygen, paillier_encrypt, paillier_decrypt, Pub, paillier_sign, paillier_verify 

API = "http://127.0.0.1:5000"
WS = "http://127.0.0.1:5000"

sio = socketio.Client()

user_id = None
priv = None
pub = None
alias = None

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

@sio.on('message')
def on_message(data):
    """Recebe mensagem: {from, cipher, len, group?, signature?}"""
    global USER_KEY_CACHE
    try:
        sender_id = data.get('from')
        sender_alias = data.get('alias', sender_id[:8])
        signature = data.get('signature') 
        
        c = int(data.get('cipher'))
        length = int(data.get('len'))
        dec = paillier_decrypt(priv, c)
        
        try:
            msg_bytes = dec.to_bytes(length, 'big')
            msg = msg_bytes.decode(errors='replace')
        except OverflowError:
            print(f"\n[ERRO Criptográfico] Falha ao converter número para bytes. A chave privada pode estar errada, o comprimento ({length}) é insuficiente ou a cifra está corrompida.")
            return

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
                print(f"\n[ERRO DE SEGURANÇA] Chave pública do remetente {sender_alias} não encontrada. Mensagem Descartada.")
                return

            if not signature:
                print(f"\n[ALERTA DE SEGURANÇA] Mensagem de {sender_alias} não possui assinatura. Mensagem Descartada.")
                return

            is_valid = paillier_verify(sender_pub, signature, msg_bytes)

            if not is_valid:
                print(f"\n[ALERTA DE SEGURANÇA] Mensagem de {sender_alias} falhou na verificação de assinatura! Mensagem Descartada.")
                return
        
        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        if 'group' in data:
            print(f"\n[{now}] [{data['group']}] {sender_alias} > {msg}")
        else:
            print(f"\n[{now}] [{sender_alias}] > {msg}")
            
    except Exception as e:
        print(f"\n[ERRO AO PROCESSAR MENSAGEM] {e}")

@sio.on('send_response')
def on_send_response(data):
    if data.get('error'):
        print('[send error]', data['error'])

@sio.on('create_group_response')
def on_create_group_response(data):
    if data.get('error'):
        print('[erro ao criar grupo]', data['error'])
    else:
        print(f"[grupo criado: {data['group']}] (privacidade: {data.get('privacy', 'public')})")

@sio.on('join_group_response')
def on_join_group_response(data):
    if data.get('error'):
        print('[erro ao entrar no grupo]', data['error'])
    else:
        print(f"[entrou no grupo: {data['group']}]")

@sio.on('leave_group_response')
def on_leave_group_response(data):
    if data.get('error'):
        print('[erro ao sair do grupo]', data['error'])
    else:
        print(f"[saiu do grupo: {data['group']}]")

@sio.on('invite_response')
def on_invite_response(data):
    if data.get('error'):
        print('[erro ao convidar]', data['error'])
    else:
        print(f"[convite enviado para {data['invited']} no grupo {data['group']}]")

@sio.event
def disconnect():
    print('[disconnected]')

def main():
    global user_id, priv, pub, alias, USER_KEY_CACHE
    alias = input('Nome de usuário: ').strip()
    user_id = str(uuid.uuid4())

    # Checar existência via HTTP
    try:
        res = requests.get(f"{API}/users").json()
        for u in res['users']:
            if u['alias'] == alias:
                print('Usuario já existe. Tente outro nome!')
                return
    except Exception as e:
        print('(Aviso: não consegui consultar /users — continuando)')

    except Exception as e:
        print('(Aviso: não consegui consultar /users — continuando)')

    # --- INÍCIO DA MODIFICAÇÃO ---
    
    print(f'[{alias}] Gerando chaves Paillier (pode demorar)...')
    pub, priv = paillier_keygen() #

    print("\n" + "="*60)
    print("  DETALHES COMPLETOS DA GERAÇÃO DE CHAVES (Terminal Local)")
    print("="*60)
    
    print("\n[ 1. CHAVE PÚBLICA (Pub) GERADA ] - (Enviada ao Servidor)")
    print("---------------------------------------------------------")
    print(f"  n (Módulo):\n  {pub.n}")
    print("\n")
    print(f"  g (Gerador Paillier):\n  {pub.g}")
    print("\n")
    print(f"  e (Expoente RSA):\n  {pub.e}")

    print("\n\n[ 2. CHAVE PRIVADA (Priv) GERADA ] - (Mantida 100% local)")
    print("---------------------------------------------------------")
    print(f"  d (Expoente RSA):\n  {priv.d}")
    print("\n")
    print(f"  lambda (Segredo Paillier):\n  {priv.lam}")
    print("\n")
    print(f"  mu (Inverso Paillier):\n  {priv.mu}")
    
    print("\n" + "="*60)
    print("Chaves geradas. Enviando Chave Pública para o servidor...")
    print("="*60 + "\n")
    
    # Esta linha continua como estava, para o registro no servidor
    pub_obj = {"n": str(pub.n), "g": str(pub.g), "n2": str(pub.n2), "e": str(pub.e)} 
    
    # --- FIM DA MODIFICAÇÃO ---

    sio.connect(WS)

    # registrar no servidor via evento
    sio.emit('register', {
        'user_id': user_id,
        'alias': alias,
        'pub_key': pub_obj
    })

    # Loop de comandos
    try:
        while True:
            cmd = input('> ').strip()

            # Mostrar usuários
            if cmd == '/users':
                try:
                    res = requests.get(f"{API}/users").json()
                    print('\nUsuários online:')
                    for u in res['users']:
                        print(f"  {u['alias']} ({u['user_id'][:8]})")
                except Exception as e:
                    print('(Erro ao consultar /users)', e)

            # Mostrar Grupos
            elif cmd == '/groups':
                try:
                    res = requests.get(f"{API}/groups").json()
                    print('\nGrupos disponíveis:')
                    for g in res['groups']:
                        print(f"  {g['name']} ({g['members']} membros) - {g.get('privacy', 'public')}")
                except Exception as e:
                    print('(Erro ao consultar /groups)', e)

            # Criar grupo
            elif cmd.startswith('/create '):
    # Remove o comando e divide o restante
                args = cmd[len('/create '):].strip()

    # Verifica se termina com "private"
                privacy = 'public'
                if args.lower().endswith(' private'):
                    privacy = 'private'
                    args = args[: -len(' private')].strip()

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

                # divide do fim para o começo
                group, target_alias = args.rsplit(' ', 1)
                group = group.strip()
                target_alias = target_alias.strip()

                if not group or not target_alias:
                    print('Formato: /invite nome_do_grupo nome_da_pessoa')
                    continue

                sio.emit('invite_user', {'group': group, 'from_id': user_id, 'target_alias': target_alias})


            # Enviar mensagem privada
            elif cmd.startswith('@'):
                try:
                    if ':' not in cmd[1:]:
                         raise ValueError('Delimiter not found')
                         
                    target_alias, msg = cmd[1:].split(':', 1)
                    target_alias = target_alias.strip()
                    msg = msg.strip()
                    
                except ValueError:
                    print('Formato: @apelido:mensagem (Use o caractere ":" para separar o nome do usuário da mensagem)')
                    continue

                if not target_alias or not msg:
                    print('Formato: @apelido:mensagem (Apelido ou mensagem não pode estar vazio)')
                    continue
                    
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
                print('[Mensagem enviada]')

            # Enviar mensagem para grupo
            elif cmd.startswith('#'):
                try:
                    if ':' not in cmd[1:]:
                         raise ValueError('Delimiter not found')
                    group, msg = cmd[1:].split(':', 1)
                    group = group.strip()
                    msg = msg.strip()
                    
                except ValueError:
                    print('Formato: #grupo:mensagem (Use o caractere ":" para separar o nome do grupo da mensagem)')
                    continue

                if not group or not msg:
                    print('Formato: #grupo:mensagem (Grupo ou mensagem não pode estar vazio)')
                    continue
                
                msg_bytes = msg.encode()
                m_int = int.from_bytes(msg_bytes, 'big')
                signature = paillier_sign(priv, msg_bytes) 
                
                try:
                    users = requests.get(f"{API}/users").json()['users']
                except Exception as e:
                    print(f"(Erro ao obter lista de usuários: {e})")
                    print("[send error] Falha ao consultar usuários para criptografia de grupo.")
                    continue

                sent_count = 0 
                
                for u in users:
                    pk = u['pub_key']
                    e_val = int(pk.get('e', 65537))
                    pub_to = Pub(int(pk['n']), int(pk['g']), int(pk['n2']), e_val)
                    cipher = paillier_encrypt(pub_to, m_int)
                    
                    sio.emit('send_group', {
                        'group': group,
                        'from_id': user_id,
                        'cipher': str(cipher),
                        'length': len(msg),
                        'signature': signature,
                        'to_id': u['user_id']
                    })
                    sent_count += 1
                
                if sent_count > 0:
                    print(f"[Mensagem enviada para grupo {group} ({sent_count} pacotes)]")
                else:
                     print("[send error] Não há usuários online para envio de grupo.")

            elif cmd == '/quit':
                break
            else:
                print('Comandos: /users, /groups, /create grupo [private], /join grupo, /leave grupo, /invite grupo nome, @apelido:msg, #grupo:msg, /quit')

    finally:
        try:
            sio.disconnect()
        except:
            pass

if __name__ == '__main__':
    main()
