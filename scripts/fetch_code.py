import os
import pandas as pd
import requests
import time

# 1. Definir a pasta do script e a pasta raiz dinamicamente
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)

# 2. Caminhos para a Extração do Código Vulnerável
INPUT_CSV = os.path.join(BASE_DIR, "data", "dataset_all_vulnerable.csv")
OUTPUT_CSV = os.path.join(BASE_DIR, "data", "dataset_vulnerable_WITH_CODE_Glibc.csv")

def fetch_file_from_github(commit_hash, file_path):
    url = f"https://raw.githubusercontent.com/bminor/glibc/{commit_hash}/{file_path}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            return f"// HTTP ERROR {response.status_code}"
    except Exception as e:
        return f"// NETWORK ERROR: {str(e)}"

def main():
    print(f"📂 A ler o dataset equilibrado: {INPUT_CSV}")
    df = pd.read_csv(INPUT_CSV)
    
    code_contents = []
    
    print(f"🌐 A fazer download de {len(df)} ficheiros em C. Por favor, aguarde...")
    for index, row in df.iterrows():
        commit = row['P_COMMIT']
        filepath = row['FilePath']
        
        print(f"   [{index+1}/{len(df)}] A extrair: {filepath} (Commit: {commit[:7]})...")
        
        code = fetch_file_from_github(commit, filepath)
        code_contents.append(code)
        time.sleep(0.5) 
        
    df['code_content'] = code_contents
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n✅ SUCESSO! Novo dataset com os códigos guardado em: {OUTPUT_CSV}")

if __name__ == "__main__":
    main()