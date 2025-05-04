import pandas as pd
import os

# Directory where the CSV files are located
dataset_dir = "dataset"  
all_csv_files = [os.path.join(dataset_dir, file) for file in os.listdir(dataset_dir) if file.endswith(".csv")]

# Combine all CSVs into a single DataFrame
dataframes = [pd.read_csv(file) for file in all_csv_files]
combined_data = pd.concat(dataframes, ignore_index=True)

# Display basic information about the combined dataset
print(f"Total rows: {combined_data.shape[0]}, Total columns: {combined_data.shape[1]}")
print(combined_data.head())

# Save the combined dataset for future use
output_path = "combined_csvs/combined_dataset.csv"
combined_data.to_csv(output_path, index=False)
print(f"Combined dataset saved at {output_path}")

try:
    print("DEBUG: Starting to read the CSVs...")
    dataframes = [pd.read_csv(file, low_memory=False) for file in all_csv_files]
    print(f"DEBUG: CSVs loaded. Total: {len(dataframes)}")

    combined_data = pd.concat(dataframes, ignore_index=True)
    print(f"DEBUG: Data combined successfully. Shape: {combined_data.shape}")

    combined_data.to_csv(output_path, index=False)
    print(f"DEBUG: Combined dataset saved at {output_path}.")
except Exception as e:
    print(f"ERROR: Failed to combine CSVs: {e}")
    raise
