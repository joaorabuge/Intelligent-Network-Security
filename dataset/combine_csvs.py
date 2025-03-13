import pandas as pd
import os

# Diretório onde estão os arquivos CSV
dataset_dir = "dataset"  # Substitua pelo caminho do diretório
all_csv_files = [os.path.join(dataset_dir, file) for file in os.listdir(dataset_dir) if file.endswith(".csv")]

# Combinar todos os CSVs em um único DataFrame
dataframes = [pd.read_csv(file) for file in all_csv_files]
combined_data = pd.concat(dataframes, ignore_index=True)

# Exibir informações básicas do dataset combinado
print(f"Total de linhas: {combined_data.shape[0]}, Total de colunas: {combined_data.shape[1]}")
print(combined_data.head())

# Salvar o dataset combinado para uso futuro
output_path = "combined_csvs/combined_dataset.csv"
combined_data.to_csv(output_path, index=False)
print(f"Dataset combinado salvo em {output_path}")

try:
    print("DEBUG: Iniciando leitura dos CSVs...")
    dataframes = [pd.read_csv(file, low_memory=False) for file in all_csv_files]
    print(f"DEBUG: CSVs carregados. Total: {len(dataframes)}")

    combined_data = pd.concat(dataframes, ignore_index=True)
    print(f"DEBUG: Dados combinados com sucesso. Formato: {combined_data.shape}")

    combined_data.to_csv(output_path, index=False)
    print(f"DEBUG: Dataset combinado salvo em {output_path}.")
except Exception as e:
    print(f"ERRO: Falha ao combinar CSVs: {e}")
    raise
