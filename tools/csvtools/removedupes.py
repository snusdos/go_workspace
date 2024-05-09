import pandas as pd

# Load the CSV file into a DataFrame
df = pd.read_csv('/Volumes/A1/resultsparsepy.csv')

# Count the number of duplicate serial numbers
duplicate_count = df.duplicated(subset=['serialnumber']).sum()

# Filter out duplicate entries based on 'serialnumber'
df_filtered = df.drop_duplicates(subset=['serialnumber'])

# Save the filtered DataFrame back to a new CSV file
df_filtered.to_csv('/Volumes/A1/filteredresultsparsepy.csv', index=False)

print("Duplicates removed:", duplicate_count)
