import requests
from requests.auth import HTTPBasicAuth
import time
import winsound  # Biblioteca nativa do Windows para emitir sons
from datetime import datetime

# ==========================================
# CONFIGURAÇÕES DO RADAR
# ==========================================
OLLAMA_ENDPOINT = "http://10.3.1.241:80/api/generate"
OLLAMA_USERNAME = 'gmarinho'
OLLAMA_PASSWORD = 'J9u2E8fQRTT5'

# Usamos o modelo de 12B como "cobaia". Se ele responder rápido, a GPU está livre.
MODEL_TO_TEST = "gemma3:12b"
INTERVALO_MINUTOS = 30  # De quanto em quanto tempo ele faz o teste (podes alterar)
LIMITE_SEGUNDOS = 15.0  # Se responder em menos de 15s, a GPU está nossa!

def enviar_sonda():
    """Faz um pedido minúsculo ao modelo para testar a velocidade."""
    payload = {
        "model": MODEL_TO_TEST,
        "prompt": "Say 'OK' and nothing else.",
        "stream": False,
        "options": {
            "num_predict": 5  # Queremos apenas uma resposta de 1 ou 2 palavras
        }
    }
    
    start_time = time.perf_counter()
    try:
        # Se demorar mais de 60 segundos, cancela logo (GPU ocupada)
        response = requests.post(
            OLLAMA_ENDPOINT, 
            json=payload, 
            auth=HTTPBasicAuth(OLLAMA_USERNAME, OLLAMA_PASSWORD),
            timeout=60
        )
        response.raise_for_status()
        latency_sec = time.perf_counter() - start_time
        return latency_sec
    except Exception:
        # Erro ou Timeout
        return -1

def iniciar_radar():
    print("==================================================")
    print(f"📡 RADAR DEI ATIVADO | Verificação a cada {INTERVALO_MINUTOS} min")
    print("==================================================")
    print("Pressione Ctrl+C a qualquer momento para parar.\n")
    
    try:
        while True:
            agora = datetime.now().strftime("%H:%M:%S")
            print(f"[{agora}] A enviar sonda de teste para a GPU...")
            
            tempo_resposta = enviar_sonda()
            
            if tempo_resposta == -1:
                print("   🔴 RESULTADO: Timeout ou Erro. A GPU está extremamente sobrecarregada.")
            elif tempo_resposta <= LIMITE_SEGUNDOS:
                print(f"   🟢 ALERTA: GPU LIVRE! Respondeu em apenas {tempo_resposta:.2f} segundos!")
                print("   🚀 PODE INICIAR O SEU BENCHMARK AGORA!")
                
                # Toca o alarme sonoro (5 beeps de alerta)
                for _ in range(5):
                    winsound.Beep(1000, 500)  # Frequência 1000Hz, Duração 500ms
                    time.sleep(0.2)
                
                # Sai do loop porque a missão foi cumprida
                break 
            else:
                print(f"   🟡 RESULTADO: GPU Ocupada (CPU Fallback). Demorou {tempo_resposta:.2f} segundos.")
            
            print(f"A aguardar {INTERVALO_MINUTOS} minutos para a próxima sondagem...\n")
            time.sleep(INTERVALO_MINUTOS * 60)
            
    except KeyboardInterrupt:
        print("\n🛑 Radar desativado manualmente.")

if __name__ == "__main__":
    iniciar_radar()