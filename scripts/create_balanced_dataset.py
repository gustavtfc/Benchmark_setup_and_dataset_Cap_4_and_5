import pandas as pd

# Caminhos
INPUT_CSV = "/home/elshaddai/vulnerability-testing/glibc-dataset/data/dump-glibc.csv" # O seu CSV sem código
OUTPUT_CSV = "/home/elshaddai/vulnerability-testing/glibc-dataset/data/dataset_balanced_30.csv"

def main():
    print("A ler o dataset gigante original...")
    df = pd.read_csv(INPUT_CSV)
    
    # 1. Isolar 15 vulneráveis (BEFORE)
    vulnerables = df[df['Occurrence'] == 'before'].head(15).copy()
    
    # 2. Isolar 15 seguros (AFTER)
    safes = df[df['Occurrence'] == 'after'].head(15).copy()
    
    # 3. Juntar tudo num só dataset misturado e baralhado
    balanced_df = pd.concat([vulnerables, safes]).sample(frac=1, random_state=42).reset_index(drop=True)
    
    print("Dataset criado com sucesso! Contagem:")
    print(balanced_df['Occurrence'].value_counts())
    
    balanced_df.to_csv(OUTPUT_CSV, index=False)
    print(f"\nGuardado em: {OUTPUT_CSV}")
    print("\n⚠️ AVISO: Agora precisamos de correr o fetch_code para ir buscar os ficheiros .c para estes 30!")

if __name__ == "__main__":
    main()