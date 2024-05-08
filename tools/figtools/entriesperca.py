import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('/Volumes/A1/filteredresultsparsepy.csv')

print(df['notBefore'].isnull().sum())

df['orgs'] = df['issuerO']

issuerOrgs = df.groupby('orgs')['serialnumber'].nunique()

issuerOrgs = issuerOrgs[issuerOrgs > 10000]
print(issuerOrgs)

plt.figure(figsize=(10, 6))
issuerOrgs.plot(kind='bar')
plt.title('Entries Grouped by Issuer Organization')
plt.xlabel('Issuer Organizations')
plt.ylabel('Number of Entries')
plt.xticks(rotation=45) 
plt.grid(True)
plt.tight_layout()  
plt.show()
