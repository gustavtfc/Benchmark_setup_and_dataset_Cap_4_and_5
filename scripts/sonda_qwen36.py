import requests
from requests.auth import HTTPBasicAuth
import pandas as pd
import os

# ==========================================
# CONFIGURAÇÕES DO SERVIDOR E PROXY
# ==========================================
OLLAMA_ENDPOINT = "http://10.3.1.226:80/api/generate"
OLLAMA_USERNAME = 'gmarinho'
OLLAMA_PASSWORD = 'J9u2E8fQRTT5'

# ESCOLHA DE MODELO TESTE
MODEL_NAME = "qwen3-coder:30b"
TEMP = 0.0

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
DATASET_PATH = os.path.join(BASE_DIR, "data", "dataset_patched_WITH_CODE_Glibc.csv")

def build_prompt(code_snippet):
    return f"""[SYSTEM]
You are an expert cybersecurity code reviewer. Your task is to analyze the provided C source code for security vulnerabilities.

[USER]
Analyze the following C function. 
1. Determine if it contains a vulnerability.
2. If vulnerable, identify the most likely CWE category.

You MUST respond strictly in the following JSON format:
{{
  "is_vulnerable": true/false,
  "cwe": "CWE-XXX" or "None",
  "reasoning": "Brief technical explanation."
}}

[CODE]
{code_snippet}
"""

def testar_modelo_conhecido():
    print(f"🚀 Iniciando Sondagem Bruta do modelo {MODEL_NAME}")
    
    try:
        df_test = pd.read_csv(DATASET_PATH)
    except FileNotFoundError:
        print(f"❌ Arquivo {DATASET_PATH} não encontrado.")
        return

    amostras = df_test.head(3)

    for index, row in amostras.iterrows():
        print(f"\n{'='*50}")
        print(f"🛠️  TESTANDO SAMPLE ID: {index}")
        print(f"{'='*50}")
        
        code_snippet = str(row.get('code_content', ''))
        prompt = build_prompt(code_snippet)
        
        payload = {
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False,
            #"format": "json",  COMENTADO PARA VISUALIZAR O TEXTO BRUTO
            "truncate": False, 
            "options": {
                "temperature": TEMP,
                "top_p": 0.9,
                "num_predict": 250,
                "num_ctx": 32000 
            }
        }
        
        try:
            response = requests.post(
                OLLAMA_ENDPOINT, 
                json=payload, 
                auth=HTTPBasicAuth(OLLAMA_USERNAME, OLLAMA_PASSWORD),
                timeout=600
            )
            response.raise_for_status()
            
            result_text = response.json().get('response', '')
            
            print(">>> RESPOSTA EXATA DO MODELO (SEM PARSER):")
            print(repr(result_text)) 
            
        except Exception as e:
            print(f"❌ Erro de conexão na amostra {index}: {str(e)}")

if __name__ == "__main__":
    testar_modelo_conhecido()