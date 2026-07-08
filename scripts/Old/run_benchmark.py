import json
import requests
import time
import pandas as pd
import re
from datetime import datetime
from pathlib import Path

# ==========================================
# CONFIGURAÇÕES DO BENCHMARK (CAPÍTULO 4 e 5)
# ==========================================
OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"

# Escalas definidas na tese: 1.5B, 7B e 14B (Base e Coder)
MODELS_TO_TEST = [
    "qwen2.5:1.5b",
    "qwen2.5-coder:1.5b",
    "qwen2.5:7b",
    "qwen2.5-coder:7b"
    # "qwen2.5:14b",       # Descomente se a sua máquina aguentar
    # "qwen2.5-coder:14b"  # Descomente se a sua máquina aguentar
]

# Dataset de entrada (Ajuste o caminho para o seu dump do glibc)
DATASET_PATH = "/home/elshaddai/vulnerability-testing/glibc-dataset/data/dump-glibc-with-code.csv"
RESULTS_DIR = "/home/elshaddai/vulnerability-testing/glibc-dataset/results"

def build_prompt(code_snippet):
    """
    Constrói o prompt Zero-Shot exato definido no Capítulo 5.
    Força a saída para o formato JSON.
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

def query_ollama(model_name, prompt):
    """Faz a requisição para a API local do Ollama com tratamento robusto de erros e limites."""
    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.0,
            "top_p": 0.9,
            "num_predict": 250 # CRÍTICO: Impede loops infinitos! O modelo só pode gerar até 250 tokens (palavras).
        }
    }

    start_time = time.perf_counter()
    try:
        response = requests.post(OLLAMA_ENDPOINT, json=payload, timeout=600)
        response.raise_for_status()
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        result_text = response.json().get('response', '')
        
        # Limpador de Markdown: Remove ```json e ``` caso o modelo decida ser "engraçadinho"
        result_text = re.sub(r'^```json\s*', '', result_text)
        result_text = re.sub(r'\s*```$', '', result_text).strip()
        
        try:
            model_output = json.loads(result_text)
            
            # Validação estrita das chaves
            is_vuln = model_output.get("is_vulnerable", False)
            if not isinstance(is_vuln, bool): # Se ele inventou texto onde devia ser True/False
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
    print("🚀 Iniciando Benchmark de Detecção de Vulnerabilidades (Fedora Local)")
    Path(RESULTS_DIR).mkdir(exist_ok=True)
    
    # 1. Carregar Dataset
    print(f"📂 Carregando dataset: {DATASET_PATH}")
    try:
        df = pd.read_csv(DATASET_PATH)
        # Para testes rápidos, vamos pegar apenas 10 amostras (5 vulneráveis, 5 seguras se possível)
        df_test = df.head(10) 
    except FileNotFoundError:
        print(f"❌ Arquivo {DATASET_PATH} não encontrado. Verifique o caminho.")
        return

    all_results = []
    total_tests = len(df_test) * len(MODELS_TO_TEST)
    current_test = 0

    # 2. Loop de Inferência
    for index, row in df_test.iterrows():
        # Assumindo que a coluna de código se chama 'code' ou similar. 
        # ATENÇÃO: Ajuste 'FilePath' ou 'Code' de acordo com o seu CSV real.
        code_snippet = row.get('code_content', f"// Code from {row.get('FilePath', 'Unknown')}\n// Insert code here")
        expected_cwe = row.get('V_CLASSIFICATION', 'Safe')
        
        prompt = build_prompt(code_snippet)
        
        for model in MODELS_TO_TEST:
            current_test += 1
            print(f"🔄 [{current_test}/{total_tests}] Testando {model} na amostra {index} (Expected: {expected_cwe})...")
            
            output, latency = query_ollama(model, prompt)
            
            # 3. Registrar Resultados
            record = {
                "sample_id": index,
                "model": model,
                "expected_cwe": expected_cwe,
                "predicted_is_vulnerable": output.get("is_vulnerable"),
                "predicted_cwe": output.get("cwe"),
                "reasoning": output.get("reasoning"),
                "latency_ms": round(latency, 2)
            }
            all_results.append(record)
            print(f"   ✅ Latência: {round(latency,2)}ms | Predição: {output.get('is_vulnerable')} | CWE: {output.get('cwe')}")

    # 4. Salvar Resultados Oficiais
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_df = pd.DataFrame(all_results)
    csv_filename = f"{RESULTS_DIR}/benchmark_results_{timestamp}.csv"
    results_df.to_csv(csv_filename, index=False)
    
    print(f"\n🎉 Benchmark Concluído! Resultados salvos em: {csv_filename}")

if __name__ == "__main__":
    main()