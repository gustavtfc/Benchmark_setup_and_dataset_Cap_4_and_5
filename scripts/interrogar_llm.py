import requests
from requests.auth import HTTPBasicAuth
import os
import time

# ======= CONFIGURAÇÕES =======
OLLAMA_ENDPOINT = "http://10.3.1.226:80/api/generate"
# Credenciais do Proxy
OLLAMA_USERNAME = 'gmarinho'
OLLAMA_PASSWORD = 'J9u2E8fQRTT5'

# Os 3 modelos que deram o falso positivo
MODELOS = [
    "devstral-32k:latest",
    "qwen2.5:14b",
    "gemma3:12b"
]

# ======= CONFIGURAÇÕES DE CAMINHO AUTOMÁTICO =======
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)

# PASSO MANUAL: Mude apenas o NOME do arquivo aqui (ex: amostra_0..., amostra_360...)
NOME_ARQUIVO = "amostra_360_patched_CVE-2021-35942.c" 

# O Python agora monta o caminho perfeito, não importa de onde você rode o terminal
ARQUIVO_ALVO = os.path.join(BASE_DIR, "data", NOME_ARQUIVO)

def main():
    print(f"📖 Lendo o arquivo: {ARQUIVO_ALVO}")
    try:
        with open(ARQUIVO_ALVO, "r", encoding="utf-8") as f:
            codigo_c = f.read()
    except Exception as e:
        print(f"❌ Erro ao ler arquivo: {e}")
        return

    print(f"✅ Código carregado. Tamanho: {len(codigo_c)} caracteres.\n")

    prompt_interrogatorio = f"""[SYSTEM]
Você é um auditor sênior de código-fonte de cibersegurança e pesquisador acadêmico especializado em análise de binários e core-libraries (glibc).

[CONTEXTO]
O código C fornecido abaixo foi extraído de uma versão corrigida (PATCHED) do repositório oficial do GNU C Library. Ele passou por auditoria humana e está validado como SEGURO. No entanto, em um teste automatizado anterior, modelos de IA classificaram este código incorretamente como VULNERÁVEL (Falso Positivo).

[TAREFA]
Analise o código fornecido e responda estritamente aos seguintes pontos de forma técnica:
1. Identifique a linha ou função exata que poderia enganar uma IA, fazendo-a pensar que há uma falha.
2. Explique tecnicamente por que o código é SEGURO. Qual é o mecanismo de defesa (bounds checking, sanitização, etc.) que o patch implementou e que costuma ser ignorado por analisadores estáticos?

[CÓDIGO]
{codigo_c}
"""

    for modelo in MODELOS:
        # Define o tamanho do contexto dinamicamente para não quebrar o servidor
        context_size = 32000 if "32k" in modelo.lower() else 8192
        
        payload = {
            "model": modelo,
            "prompt": prompt_interrogatorio,
            "stream": False,
            "truncate": False,
            "options": {
                "temperature": 0.1, 
                "num_ctx": context_size
            }
        }

        print(f"🚀 Interrogando {modelo}...")
        start_time = time.perf_counter()
        
        try:
            response = requests.post(
                OLLAMA_ENDPOINT, 
                json=payload, 
                auth=HTTPBasicAuth(OLLAMA_USERNAME, OLLAMA_PASSWORD),
                timeout=600
            )
            response.raise_for_status()
            
            resposta_ia = response.json().get('response', '')
            tempo_total = round(time.perf_counter() - start_time, 2)
            
            print(f"================ RESPOSTA: {modelo} ({tempo_total}s) ================")
            print(resposta_ia)
            print("================================================================\n")
            
        except Exception as e:
            print(f"❌ Falha no modelo {modelo}: {e}\n")

if __name__ == "__main__":
    main()