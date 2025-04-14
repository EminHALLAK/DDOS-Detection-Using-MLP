import pandas as pd
import glob

# Path to your CSV files. Adjust the path and pattern as needed.
csv_files = glob.glob("ddos/*.csv")

# Read and concatenate all CSVs into one DataFrame
df_list = [pd.read_csv(file) for file in csv_files]
merged_df = pd.concat(df_list, ignore_index=True)

# Optionally, save the merged DataFrame to a new CSV file
merged_df.to_csv("merged_ddos_dataset.csv", index=False)

print(f"Merged {len(csv_files)} files into one dataset with {len(merged_df)} rows.")