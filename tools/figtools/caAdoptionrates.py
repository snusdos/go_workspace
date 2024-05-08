import pandas as pd
import matplotlib.pyplot as plt

# Load the data
df = pd.read_csv('/Volumes/A1/filteredresultsparsepy.csv')

df['notBefore'] = pd.to_datetime(df['notBefore'])
df['notAfter'] = pd.to_datetime(df['notAfter'])

df['Year'] = df['notBefore'].dt.year

specified_issuer = "COMODO CA Limited"  

issuer_data = df[df['issuerO'] == specified_issuer]

total_per_year = issuer_data.groupby('Year').size()
print(total_per_year)
filled_per_year = issuer_data[issuer_data['CRL'].notna()].groupby('Year').size()
print(filled_per_year)
ratio_per_year = (filled_per_year / total_per_year * 100).dropna()

# Plot
plt.figure(figsize=(10, 6))
ratio_per_year.plot(kind='bar')
plt.title(f'Percentage CRL Occurances in Dataset per Year for {specified_issuer}')
plt.xlabel('Year')
plt.ylabel('Percentage of CRLs')
plt.grid(True)
plt.tight_layout()
plt.show()
