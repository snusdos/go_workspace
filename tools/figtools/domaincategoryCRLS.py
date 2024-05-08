import pandas as pd
import matplotlib.pyplot as plt

# Load the data
df = pd.read_csv('/Users/simonstensson/Projects/go_workspace/resultsparsepy.csv')

def extract_tld(domain):
    # Handle NaN values and ensure the domain is a string
    if pd.notna(domain):
        return domain.split('.')[-1]
    else:
        return 'Unknown'  # You can return None or 'Unknown' as needed

# Categorize the TLD
def categorize_tld(tld):
    categories = {
        'com': 'Commercial',
        'org': 'Organization',
        'net': 'Network services',
        'gov': 'Government',
        'edu': 'Educational',
        'mil': 'Military',
        'biz': 'Business',
        'Unknown': 'Unknown',  # Handling Unknown TLDs
        # Add more as needed
    }
    return categories.get(tld, 'Other')  

df['TLD'] = df['subjectCN'].apply(extract_tld)
df['Category'] = df['TLD'].apply(categorize_tld)

df['HasCRL'] = df['CRL'].notna()

category_counts = df.groupby('Category').size()
crl_presence_counts = df[df['HasCRL']].groupby('Category').size()
crl_percentage = (crl_presence_counts / category_counts) * 100

# Plot
plt.figure(figsize=(10, 6))
crl_percentage.plot(kind='bar')
plt.title('Percentage of CRLs Among Top Domain Categories')
plt.xlabel('Domain Category')
plt.ylabel('Percentage of Entries with CRL')
plt.ylim(0, 100) 
plt.xticks(rotation=45) 
plt.grid(True)
plt.tight_layout()  
plt.show()
