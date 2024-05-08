import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("/Volumes/A1/filteredresultsparsepy.csv")

df['notBefore'] = pd.to_datetime(df['notBefore'], format='%Y%m%d%H%M%S'+'Z')
df['notAfter'] = pd.to_datetime(df['notAfter'], format='%Y%m%d%H%M%S'+'Z')

df['Year'] = df['notBefore'].dt.year

crl_counts = df.groupby(['Year', 'CRL']).size().unstack(fill_value=0)

total_certificates_per_year = df.groupby('Year').size()

normalized_crl_counts = crl_counts.div(total_certificates_per_year, axis=0)

normalized_crl_counts.plot(kind='bar', stacked=True)
plt.xlabel('Year')
plt.ylabel('Proportion of CRL')
plt.title('Proportion of CRL per Year')
plt.legend(title='CRL', bbox_to_anchor=(1.05, 1), loc='upper left')
plt.show()
