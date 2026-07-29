import os
import pandas as pd
import requests
import time
import sys

# 1. Mapeamento dinâmico das pastas
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(BASE_DIR, "data")

# 2. Caminhos locais exatos para os metadados que você baixou
PROJECT_INFO = os.path.join(DATA_DIR, "cwe-bench-java", "data", "project_info.csv")
FIX_INFO = os.path.join(DATA_DIR, "cwe-bench-java", "data", "fix_info.csv")

# 3. Caminhos de saída finais
OUTPUT_VULN = os.path.join(DATA_DIR, "dataset_java_vulnerable_WITH_CODE.csv")
OUTPUT_PATCHED = os.path.join(DATA_DIR, "dataset_java_patched_WITH_CODE.csv")

def fetch_file_from_github(username, repo, commit_hash, file_path):
    """Extrai o código diretamente da versão específica no GitHub"""
    url = f"https://raw.githubusercontent.com/{username}/{repo}/{commit_hash}/{file_path}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            return f"// HTTP ERROR {response.status_code}"
    except Exception as e:
        return f"// NETWORK ERROR: {str(e)}"

def main():
    print("🔍 A verificar a estrutura de pastas local...")
    
    # Trava de segurança para garantir que os ficheiros estão no lugar certo
    if not os.path.exists(PROJECT_INFO):
        print(f"❌ ERRO: Não foi possível encontrar o ficheiro project_info.csv.")
        print(f"   Por favor, verifique se ele está exatamente neste caminho:\n   {PROJECT_INFO}")
        sys.exit(1)
        
    if not os.path.exists(FIX_INFO):
        print(f"❌ ERRO: Não foi possível encontrar o ficheiro fix_info.csv.")
        print(f"   Por favor, verifique se ele está exatamente neste caminho:\n   {FIX_INFO}")
        sys.exit(1)

    print("📂 Carregando metadados locais do CWE-Bench-Java...")
    df_proj = pd.read_csv(PROJECT_INFO)
    df_fix = pd.read_csv(FIX_INFO)
    
    # Cruzamento de dados
    df_merged = pd.merge(df_fix, df_proj[['project_slug', 'buggy_commit_id', 'cwe_id']], on='project_slug')
    
    vuln_dataset = []
    patched_dataset = []
    
    print(f"🌐 Iniciando extração remota do código-fonte ({len(df_merged)} pares). Aguarde...")
    
    for index, row in df_merged.iterrows():
        username = row['github_username']
        repo = row['github_repository_name']
        filepath = row['file']
        
        commit_buggy = row['buggy_commit_id']
        commit_fix = row['commit'] 
        
        print(f"   [{index+1}/{len(df_merged)}] A extrair código: {filepath} ({repo})...")
        
        # 1. Versão Vulnerável
        code_vuln = fetch_file_from_github(username, repo, commit_buggy, filepath)
        vuln_dataset.append({
            "project_slug": row['project_slug'],
            "FilePath": filepath,
            "code_content": code_vuln,
            "V_CLASSIFICATION": row['cwe_id']
        })
        
        # 2. Versão Corrigida
        code_patched = fetch_file_from_github(username, repo, commit_fix, filepath)
        patched_dataset.append({
            "project_slug": row['project_slug'],
            "FilePath": filepath,
            "code_content": code_patched,
            "V_CLASSIFICATION": "Safe"
        })
        
        time.sleep(0.5) 
        
    # Salvar resultados
    pd.DataFrame(vuln_dataset).to_csv(OUTPUT_VULN, index=False)
    pd.DataFrame(patched_dataset).to_csv(OUTPUT_PATCHED, index=False)
    
    print(f"\n✅ SUCESSO! Datasets finais gerados e prontos para o run_benchmark_DEI.py:")
    print(f"   -> {OUTPUT_VULN}")
    print(f"   -> {OUTPUT_PATCHED}")

if __name__ == "__main__":
    main()