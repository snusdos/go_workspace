import requests

def getTotalCerts(file_path):
    total_certs = 0
    format_number = lambda x: "{:,}".format(x)  # Format numbers with commas
    with open(file_path, 'r') as file:
        for line in file:
            print(line)
            log_url = line.strip()
            if not log_url:
                continue  # Skip empty lines or improperly formatted URLs

            try:
                response = requests.get(f'https://{log_url}ct/v1/get-sth', timeout=3)
                if response.status_code == 200:
                    log_info = response.json()
                    total_certs += int(log_info['tree_size'])
                    print(f"{log_url} has {format_number(log_info['tree_size'])} certificates")
                else:
                    print(f"Failed to fetch data for {log_url}: HTTP {response.status_code}")
            except Exception as e:
                print(f"Failed to get information for {log_url}: {e}")

    print(f"Total certs -> {format_number(total_certs)}")

getTotalCerts("data/parse1.txt")