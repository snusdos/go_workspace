import requests


def fetch_log_urls_and_save():
    url = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
    output_file = "log_urls.txt"
    
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raises an HTTPError for bad responses
        data = response.json()
        
        urls = []
        # Navigate through the JSON structure
        for operator in data.get("operators", []):
            for log in operator.get("logs", []):
                if "url" in log:
                    urls.append(log["url"])
        
        # Write URLs to a file
        with open(output_file, "w") as file:
            for url in urls:
                file.write(url + "\n")
                
        return f"URLs have been written to {output_file}"
    except requests.RequestException as e:
        return f"An error occurred: {e}"

# Uncomment the following line to test the function after reviewing and finalizing
fetch_log_urls_and_save()


