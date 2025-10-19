import socketio
import requests
import uuid
import threading
import time
from paillier import paillier_keygen, paillier_encrypt, paillier_decrypt, Pub

API = "http://127.0.0.1:5000"
WS = "http://127.0.0.1:5000"

sio = socketio.Client()

user_id = None
priv = None
pub = None
alias = None

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
    """Recebe mensagem: {from, cipher, len, group?}"""
    try:
        import datetime
        sender = data.get('alias', data.get('from')[:8])
        c = int(data.get('cipher'))
        length = int(data.get('len'))
        dec = paillier_decrypt(priv, c)
        msg = dec.to_bytes(length, 'big').decode(errors='replace')

        # Adicionar timestamp formatado
        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        if 'group' in data:
            print(f"\n[{now}] [{data['group']}] {sender} > {msg}")
        else:
            print(f"\n[{now}] [{sender}] > {msg}")
    except Exception as e:
        pass


@sio.on('send_response')
def on_send_response(data):
    if data.get('error'):
        print('[send error]', data['error'])
    else:
        if 'group' in data:
            print(f"[Mensagem enviada para grupo {data['group']}]")
        else:
            print('[Mensagem enviada]')

@sio.on('create_group_response')
def on_create_group_response(data):
    if data.get('error'):
        print('[erro ao criar grupo]', data['error'])
    else:
        print(f"[grupo criado: {data['group']}]")

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

@sio.event
def disconnect():
    print('[disconnected]')

def main():
    global user_id, priv, pub, alias
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

    print(f'[{alias}] Gerando chaves Paillier...')
    pub, priv = paillier_keygen()
    pub_obj = {"n": str(pub.n), "g": str(pub.g), "n2": str(pub.n2)}

    # conectar via Socket.IO
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
                        print(f"  {g['name']} ({g['members']} membros)")
                except Exception as e:
                    print('(Erro ao consultar /groups)', e)

            # Criar grupo
            elif cmd.startswith('/create '):
                group = cmd.split(' ', 1)[1]
                sio.emit('create_group', {'group': group, 'user_id': user_id})

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

            # Enviar mensagem privada
            elif cmd.startswith('@'):
                try:
                    # Novo formato: @apelido:mensagem. Usa o ':' como separador
                    if ':' not in cmd[1:]:
                         raise ValueError('Delimiter not found')
                         
                    target_alias, msg = cmd[1:].split(':', 1)
                    target_alias = target_alias.strip() # Nome do usuário, incluindo espaços
                    msg = msg.strip() # Mensagem
                    
                except ValueError:
                    print('Formato: @apelido:mensagem (Use o caractere ":" para separar o nome do usuário da mensagem)')
                    continue

                if not target_alias or not msg:
                    print('Formato: @apelido:mensagem (Apelido ou mensagem não pode estar vazio)')
                    continue
                    
                users = requests.get(f"{API}/users").json()['users']
                # Busca exata pelo alias multi-palavra (sem .lower() se o alias tiver sensibilidade a maiúsculas)
                target = next((u for u in users if u['alias'] == target_alias), None) 
                
                if not target:
                    print('Usuário não encontrado.')
                    continue

                # Criptografia e Envio
                pk = target['pub_key']
                pub_to = Pub(int(pk['n']), int(pk['g']), int(pk['n2']))
                m_int = int.from_bytes(msg.encode(), 'big')
                cipher = paillier_encrypt(pub_to, m_int)

                sio.emit('send', {
                    'from_id': user_id,
                    'to_id': target['user_id'],
                    'cipher': str(cipher),
                    'length': len(msg)
                })

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
                
                m_int = int.from_bytes(msg.encode(), 'big')
                cipher = paillier_encrypt(pub, m_int) 

                sio.emit('send_group', {
                    'group': group,
                    'from_id': user_id,
                    'cipher': str(cipher),
                    'length': len(msg)
                })
        
                users = requests.get(f"{API}/users").json()['users']

                for u in users:
                    pk = u['pub_key']
                    pub_to = Pub(int(pk['n']), int(pk['g']), int(pk['n2']))
                    m_int = int.from_bytes(msg.encode(), 'big')
                    cipher = paillier_encrypt(pub_to, m_int)
                    sio.emit('send_group', {
                        'group': group,
                        'from_id': user_id,
                        'cipher': str(cipher),
                        'length': len(msg)
                    })

            elif cmd == '/quit':
                break
            else:
                print('Comandos: /users, /groups, /create grupo, /join grupo, /leave grupo, @apelido:msg, #grupo:msg, /quit')

    finally:
        try:
            sio.disconnect()
        except:
            pass

if __name__ == '__main__':
    main()
