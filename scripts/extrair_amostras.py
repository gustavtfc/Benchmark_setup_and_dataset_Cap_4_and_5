import pandas as pd
import os

# Caminhos absolutos
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
DATASET_ORIGINAL = os.path.join(BASE_DIR, "data", "dataset_patched_WITH_CODE_Glibc.csv")

# As 3 amostras críticas que falharam (IDs são os índices da linha no CSV)
AMOSTRAS_ALVO = [0, 360, 361]

def main():
    print(f"📥 Lendo o dataset original: {DATASET_ORIGINAL}")
    try:
        df = pd.read_csv(DATASET_ORIGINAL)
    except FileNotFoundError:
        print(f"❌ Erro: Arquivo não encontrado no caminho {DATASET_ORIGINAL}")
        return

    print("🔍 Iniciando extração cirúrgica do código-fonte...")
    
    for amostra_id in AMOSTRAS_ALVO:
        try:
            # O sample_id do benchmark corresponde ao índice (linha) do CSV original
            linha = df.iloc[amostra_id]
            codigo = linha['code_content']
            cve = linha['CVE']
            
            # Cria um arquivo .c limpo para esta amostra
            nome_arquivo = os.path.join(BASE_DIR, "data", f"amostra_{amostra_id}_patched_{cve}.c")
            
            with open(nome_arquivo, "w", encoding="utf-8") as f:
                f.write(str(codigo))
                
            print(f"✅ Amostra {amostra_id} ({cve}) extraída! Tamanho: {len(str(codigo))} caracteres. Salvo em: {nome_arquivo}")
            
        except IndexError:
            print(f"⚠️ Erro: Amostra {amostra_id} não existe no índice do CSV.")
        except Exception as e:
            print(f"⚠️ Erro inesperado na amostra {amostra_id}: {e}")

if __name__ == "__main__":
    main()