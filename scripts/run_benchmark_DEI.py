import json
import requests
from requests.auth import HTTPBasicAuth  # <-- Biblioteca necessária para o login
import time
import pandas as pd
import re
import csv
import os
from datetime import datetime
from pathlib import Path

# ==========================================
# CONFIGURAÇÕES DO BENCHMARK (CAPÍTULO 4 e 5)
# ==========================================
# NOVO ENDPOINT ATUALIZADO: Porta 80
OLLAMA_ENDPOINT = "http://10.3.1.226:80/api/generate"

# Credenciais do Proxy
OLLAMA_USERNAME = 'gmarinho'
OLLAMA_PASSWORD = 'J9u2E8fQRTT5'

# 1. Pega no caminho exato onde este script está (pasta 'scripts')
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Volta uma pasta para trás para chegar à raiz do projeto
BASE_DIR = os.path.dirname(SCRIPT_DIR)

# 3. Agora junta as pastas corretas a partir da raiz
DATASET_PATH = os.path.join(BASE_DIR, "data", "dataset_patched_WITH_CODE_Glibc.csv")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

# A lista de modelos para o teste parcial seguro
# A lista definitiva de modelos para o dataset completo
MODELS_TO_TEST = [
    #"codellama:7b",
    "gemma3:12b",
    #"qwen2.5:14b",
    #"qwen2.5-coder:14b",
    #"devstral-32k:latest",
    #"qwen3.6:35b",
    #"deepseek-coder-v2:latest"

#Adicionais
    #"Llama2:7b"
    #"gemma4:31b"
    #"qwen3-coder:30b"
    #"llama3.1:70b"
]

# NOVO: Lista de temperaturas para testar cientificamente
TEMPERATURES_TO_TEST = [0.0, 0.2]

def build_prompt(code_snippet):
    """
    Constrói o prompt Zero-Shot validado.
    Força a saída para o formato JSON estrito.
    """
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

def query_ollama(model_name, prompt, temp):
    """Faz a requisição para a API local com tratamento robusto de erros e Proxy Auth."""
    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "truncate": False,  # <--- 1. A EXIGÊNCIA DO PROFESSOR (Proíbe o corte silencioso)
        "options": {
            "temperature": temp,
            "top_p": 0.9,
            "num_predict": 250,
            "num_ctx": 32000    # <--- 2. EXPANDE A JANELA DE CONTEXTO (Para ficheiros de 70.000+ chars)
        }
    }

    start_time = time.perf_counter()
    try:
        # AQUI ESTÁ A MAGIA DO PROXY: Adicionamos o auth e mantemos o POST
        response = requests.post(
            OLLAMA_ENDPOINT, 
            json=payload, 
            auth=HTTPBasicAuth(OLLAMA_USERNAME, OLLAMA_PASSWORD),
            timeout=600
        )
        response.raise_for_status()
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        result_text = response.json().get('response', '')
        
        # Limpador de Markdown
        result_text = re.sub(r'^```json\s*', '', result_text)
        result_text = re.sub(r'\s*```$', '', result_text).strip()
        
        try:
            model_output = json.loads(result_text)
            
            is_vuln = model_output.get("is_vulnerable", False)
            if not isinstance(is_vuln, bool):
                is_vuln = False
                
            cwe = str(model_output.get("cwe", "None"))
            reasoning = str(model_output.get("reasoning", "Sem justificação."))
            
            return {"is_vulnerable": is_vuln, "cwe": cwe, "reasoning": reasoning}, latency_ms
            
        except json.JSONDecodeError:
            return {"is_vulnerable": False, "cwe": "PARSE_ERROR", "reasoning": "Output não era um JSON válido."}, latency_ms
            
    except Exception as e:
        latency_ms = (time.perf_counter() - start_time) * 1000
        print(f"   ⚠️ Erro na API para o modelo {model_name}: {str(e)}")
        return {"is_vulnerable": False, "cwe": "API_ERROR", "reasoning": str(e)}, latency_ms

def main():
    print("🚀 Iniciando Benchmark de Detecção de Vulnerabilidades (Via Proxy)")
    Path(RESULTS_DIR).mkdir(parents=True, exist_ok=True)
    
    print(f"📂 Carregando dataset: {DATASET_PATH}")
    try:
        df_test = pd.read_csv(DATASET_PATH)
    except FileNotFoundError:
        print(f"❌ Arquivo {DATASET_PATH} não encontrado. Verifique o caminho.")
        return

    total_tests = len(df_test) * len(MODELS_TO_TEST)
    current_test = 0

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = os.path.join(RESULTS_DIR, f"benchmark_DEI_PROXY_results_{timestamp}.csv")

    print(f"💾 Os resultados serão gravados em tempo real no ficheiro: {csv_filename}\n")

    for index, row in df_test.iterrows():
        code_snippet = str(row.get('code_content', f"// Code from {row.get('FilePath', 'Unknown')}\n// Insert code here"))
        expected_cwe = row.get('V_CLASSIFICATION', 'Safe')
        
        #MAX_CHARS = 25000 
        #if len(code_snippet) > MAX_CHARS:
         #   print(f"   ⏩ [PULANDO] Amostra {index} é gigante ({len(code_snippet)} caracteres). Ignorando para salvar tempo.")
          #  for model in MODELS_TO_TEST:
           #     current_test += 1
            #    record = {
             #       "sample_id": index,
              #      "model": model,
               #     "expected_cwe": expected_cwe,
                #    "predicted_is_vulnerable": False,
                 #   "predicted_cwe": "SKIPPED_SIZE",
                  #  "reasoning": f"Ficheiro excedeu limite máximo de contexto ({len(code_snippet)} chars).",
                   # "latency_ms": 0.0
                #}
                #file_exists = os.path.isfile(csv_filename)
                #with open(csv_filename, mode='a', newline='', encoding='utf-8') as f:
                 #   writer = csv.DictWriter(f, fieldnames=record.keys())
                  #  if not file_exists:
                   #     writer.writeheader()
                    #writer.writerow(record)
            #continue 
        
        prompt = build_prompt(code_snippet)
        
        for model in MODELS_TO_TEST:
            for temp in TEMPERATURES_TO_TEST:  # <--- ESSA É A LINHA QUE PROVAVELMENTE FALTOU
                current_test += 1
                print(f"🔄 [{current_test}/{total_tests}] Testando {model} | Temp: {temp} na amostra {index} (Expected: {expected_cwe})...")
                
                # Agora o Python sabe quem é o 'temp'
                output, latency = query_ollama(model, prompt, temp)
                
                record = {
                    "sample_id": index,
                    "model": model,
                    "temperature": temp,
                    "expected_cwe": expected_cwe,
                    "predicted_is_vulnerable": output.get("is_vulnerable"),
                    "predicted_cwe": output.get("cwe"),
                    "reasoning": output.get("reasoning"),
                    "latency_ms": round(latency, 2)
                }
                
                file_exists = os.path.isfile(csv_filename)
                with open(csv_filename, mode='a', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=record.keys())
                    if not file_exists:
                        writer.writeheader()
                    writer.writerow(record)
                
                print(f"   ✅ Latência: {round(latency,2)}ms | Predição: {output.get('is_vulnerable')} | CWE: {output.get('cwe')}")

if __name__ == "__main__":
    main()