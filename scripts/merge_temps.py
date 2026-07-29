import pandas as pd
import os

def merge_and_sort_temperature_data(original_csv_path, temp05_csv_path, output_csv_path):
    print(f"\n🔄 INICIANDO FUSÃO E ORDENAÇÃO DOS DADOS...")
    
    try:
        # Carregar os dois arquivos
        df_original = pd.read_csv(original_csv_path)
        df_new = pd.read_csv(temp05_csv_path)
        
        # Juntar os dados (empilhar inicialmente)
        df_merged = pd.concat([df_original, df_new], ignore_index=True)
        
        # Identificar as colunas dinamicamente para ordenação
        # Assumindo que a coluna 0 é o ID e a coluna 2 é a Temperatura
        coluna_id = df_merged.columns[0]
        coluna_temp = df_merged.columns[2]
        
        # ORDENAR os dados: primeiro pelo ID, depois pela Temperatura
        df_merged = df_merged.sort_values(by=[coluna_id, coluna_temp])
        
        # Salvar o resultado organizado
        df_merged.to_csv(output_csv_path, index=False)
        
        print(f"✅ SUCESSO! Dados unidos e organizados perfeitamente.")
        print(f"💾 Novo arquivo gerado: {os.path.basename(output_csv_path)}")
        print(f"📊 Total de linhas: {len(df_merged)}")
        
    except FileNotFoundError as e:
        print(f"❌ ERRO: Arquivo não encontrado - {e.filename}. Verifique os nomes.")
    except Exception as e:
        print(f"❌ ERRO INESPERADO: {e}")

if __name__ == "__main__":
    
    # Exemplo para os dados Vulneráveis:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    RESULTS_DIR = os.path.join(BASE_DIR, "results")
    
    # Substitui pelos nomes exatos dos teus ficheiros na pasta results
    ficheiro_original = os.path.join(RESULTS_DIR, "benchmark_DEI_PROXY_results_20260720_qwen3-coder_30b_Vulnerable.csv")
    ficheiro_temp05 = os.path.join(RESULTS_DIR, "benchmark_DEI_PROXY_results_20260722_qwen3-coder_30b_Vulnerable_05.csv")
    
    # Nome do novo ficheiro final que será gerado
    ficheiro_final = os.path.join(RESULTS_DIR, "benchmark_DEI_PROXY_results_Qwen3-coder_30b_Vulnerable_MERGED.csv")
    
    # Executar a fusão
    merge_and_sort_temperature_data(ficheiro_original, ficheiro_temp05, ficheiro_final)

        # Exemplo para os dados Patched:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    RESULTS_DIR = os.path.join(BASE_DIR, "results")
    
    # Substitui pelos nomes exatos dos teus ficheiros na pasta results Patched
    ficheiro_original = os.path.join(RESULTS_DIR, "benchmark_DEI_PROXY_results_20260720_qwen3-coder_30b_Patched.csv")
    ficheiro_temp05 = os.path.join(RESULTS_DIR, "benchmark_DEI_PROXY_results_20260722_qwen3-coder_30b_Patched_05.csv")
    
    # Nome do novo ficheiro final que será gerado
    ficheiro_final = os.path.join(RESULTS_DIR, "benchmark_DEI_PROXY_results_Qwen3-coder_30b_Patched_MERGED.csv")
    
    # Executar a fusão
    merge_and_sort_temperature_data(ficheiro_original, ficheiro_temp05, ficheiro_final)
    
    