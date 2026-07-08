import requests
from requests.auth import HTTPBasicAuth

# Endpoint para listar as tags/modelos no servidor novo (porta 80)
OLLAMA_ENDPOINT = "http://10.3.1.226:80/api/tags"

# Credenciais do Proxy
OLLAMA_USERNAME = 'gmarinho'
OLLAMA_PASSWORD = 'J9u2E8fQRTT5'

print("🔍 Buscando modelos disponíveis no servidor do DEI...")

try:
    response = requests.get(
        OLLAMA_ENDPOINT,
        auth=HTTPBasicAuth(OLLAMA_USERNAME, OLLAMA_PASSWORD),
        timeout=15
    )
    response.raise_for_status()
    
    models = response.json().get("models", [])
    
    print(f"\n✅ Foram encontrados {len(models)} modelos:")
    for m in models:
        # Pega o nome do modelo e o tamanho em GB
        size_gb = m.get('size', 0) / (1024 ** 3)
        print(f" - {m['name']} (Tamanho: {size_gb:.2f} GB)")
        
except Exception as e:
    print(f"❌ Erro ao conectar com o servidor: {e}")