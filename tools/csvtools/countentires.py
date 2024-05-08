import pandas as pd

# Load the CSV file into a DataFrame
df = pd.read_csv('/Volumes/A1/filteredresultsparsepy.csv')

# Count the number of rows in the DataFrame
row_count = len(df)

print("Total rows in CSV:", row_count)
