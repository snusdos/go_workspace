import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('/Users/simonstensson/Projects/go_workspace/certificates_info.csv')

print(df['notBefore'].isnull().sum())

df['Year'] = df['notBefore'].str.slice(0, 4)

year_counts = df.groupby('Year')['serialnumber'].nunique()

year_counts = year_counts[year_counts > 1000]
print(year_counts)

plt.figure(figsize=(10, 6))
year_counts.plot(kind='bar')
plt.title('Entries Grouped by Year')
plt.xlabel('Year')
plt.ylabel('Number of Entries')
plt.grid(True)
plt.show()
