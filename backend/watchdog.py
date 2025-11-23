import subprocess
import time
import sys
import os

# Servidor sendo monitorado
SERVER_SCRIPT = "server_socketio.py"

def run_server():
    print(f"[*] WATCHDOG: Iniciando servidor de chat seguro ({SERVER_SCRIPT})...")
    # Inicia o servidor usando o mesmo Python que está rodando este script
    return subprocess.Popen([sys.executable, SERVER_SCRIPT])

if __name__ == "__main__":
    print("--- MONITOR DE DISPONIBILIDADE (WATCHDOG) ---")
    print("Este script garante que o servidor reinicie se houver falhas.")
    print("Pressione Ctrl+C para parar tudo.")
    
    while True:
        try:
            # Inicia o processo do servidor
            process = run_server()
            
            # Fica esperando o processo terminar (seja por erro ou comando de parada)
            exit_code = process.wait()
            
            # Se o código de saída for diferente de 0, houve erro/crash
            if exit_code != 0:
                print(f"\n[!] ALERTA CRÍTICO: O servidor caiu (Código de erro {exit_code}).")
                print("[*] AÇÃO AUTOMÁTICA: Reiniciando em 2 segundos...\n")
                time.sleep(2)
            else:
                # Se o código for 0, foi um encerramento normal/manual
                print("[*] Servidor desligado manualmente. Guardian encerrando.")
                break
                
        except KeyboardInterrupt:
            print("\n[!] Watchdog interrompido pelo usuário. Encerrando servidor...")
            process.terminate()
            break
        except Exception as e:
            print(f"[!] Erro inesperado no Watchdog: {e}")
            time.sleep(2)