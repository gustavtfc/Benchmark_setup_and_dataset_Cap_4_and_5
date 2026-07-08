import pandas as pd
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(BASE_DIR, "data")

INPUT_CSV = os.path.join(DATA_DIR, "dump-glibc.csv")
OUTPUT_VULNERABLE = os.path.join(DATA_DIR, "dataset_all_vulnerable.csv")
OUTPUT_PATCHED = os.path.join(DATA_DIR, "dataset_all_patched.csv")

def main():
    print(f"📥 Lendo o dataset: {INPUT_CSV}")
    try:
        df = pd.read_csv(INPUT_CSV)
    except FileNotFoundError:
        print(f"❌ Erro: Não encontrei o arquivo {INPUT_CSV}.")
        return
        
    print("🧹 Limpando o dataset (Removendo arquivos de teste)...")
    # A MÁGICA: Remove qualquer linha onde o FilePath contenha 'bug', 'tst' ou 'test'
    df_limpo = df[~df['FilePath'].str.contains(r'bug|tst|test', case=False, na=False)].copy()
    
    print("🔍 Maximizando os pares perfeitos (Before e After)...")
    
    vulnerable_list = []
    patched_list = []
    
    # Agrupar os dados por CVE
    grouped = df_limpo.groupby('CVE')
    
    for cve, group in grouped:
        # Separar before e after dentro deste CVE específico
        before_rows = group[group['Occurrence'] == 'before']
        after_rows = group[group['Occurrence'] == 'after']
        
        # Quantos pares perfeitos conseguimos fazer?
        min_pairs = min(len(before_rows), len(after_rows))
        
        if min_pairs > 0:
            vulnerable_list.append(before_rows.head(min_pairs))
            patched_list.append(after_rows.head(min_pairs))
            
    # Juntar todas as listas num DataFrame final
    if vulnerable_list and patched_list:
        df_vulnerable = pd.concat(vulnerable_list).reset_index(drop=True)
        df_patched = pd.concat(patched_list).reset_index(drop=True)
        
        print(f"\n✅ Simetria Perfeita Alcançada (Sem arquivos de teste)!")
        print(f"🔴 Arquivo Vulnerável: {len(df_vulnerable)} linhas.")
        print(f"🟢 Arquivo Corrigido: {len(df_patched)} linhas.")
        
        if len(df_vulnerable) == len(df_patched):
            print("🎯 SUCESSO: Os arquivos têm exatamente o mesmo tamanho!")
        
        # Gravar arquivos
        df_vulnerable.to_csv(OUTPUT_VULNERABLE, index=False)
        df_patched.to_csv(OUTPUT_PATCHED, index=False)
        print("💾 Arquivos salvos na pasta 'data'!")
    else:
        print("❌ Nenhum par encontrado após a limpeza!")

if __name__ == "__main__":
    main()