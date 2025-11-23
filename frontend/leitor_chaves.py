import pickle
import os
import sys

# Adiciona o diretório raiz ao path para encontrar o paillier.py
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    # Importa as classes Pub e Priv para o pickle funcionar
    from paillier import Pub, Priv 
except ImportError:
    print("Erro: Não encontrei o arquivo 'paillier.py' no diretório raiz.")
    sys.exit(1)

# Pasta onde as chaves são salvas
KEYS_DIR = "keys"

print("--- Lendo Chaves Salvas na Pasta 'frontend/keys' ---")

try:
    # Lista todos os arquivos .key na pasta
    for filename in os.listdir(KEYS_DIR):
        if filename.endswith(".key"):
            filepath = os.path.join(KEYS_DIR, filename)

            try:
                with open(filepath, 'rb') as f:
                    # Carrega os dados do arquivo
                    identity_data = pickle.load(f)

                print(f"\n========================================")
                print(f" ARQUIVO: {filename}")
                print(f"========================================")
                print(f"  Usuário (alias): {identity_data['alias']}")
                print(f"  User ID: {identity_data['user_id']}")

                print("\n  [ CHAVE PÚBLICA ]")
                print(f"    n (Módulo): {identity_data['pub'].n}")
                print(f"    e (Expoente RSA): {identity_data['pub'].e}")

                print("\n  [ CHAVE PRIVADA (SECRETA) ]")
                print(f"    d (Expoente RSA): {identity_data['priv'].d}")
                print(f"    lambda (Paillier): {identity_data['priv'].lam}")
                print(f"    mu (Paillier): {identity_data['priv'].mu}")

            except Exception as e:
                print(f"\n--- Erro ao ler {filename}: {e} ---")
                print("    (Este arquivo pode estar corrompido ou ser de uma versão antiga)")

except FileNotFoundError:
    print(f"Erro: Pasta '{KEYS_DIR}' não encontrada. Rode este script de dentro da pasta 'frontend/'.")
except Exception as e:
    print(f"Um erro ocorreu: {e}")