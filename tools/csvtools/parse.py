import csv
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from OpenSSL import crypto

# Constants
FOLDER_PATH = "C:/Users/simon/go_workspace/data/testpem"
OUTPUT_FILE = "C:/Users/simon/go_workspace/result.csv"
NUM_WORKERS = 10  # Number of threads, adjust based on the system capabilities

# CSV headers
CSV_HEADERS = ['serialnumber', 'subjectC', 'subjectCN', 'subjectL', 'subjectO', 'subjectOU',
               'issuerC', 'issuerCN', 'issuerL', 'issuerO', 'issuerOU', 'notBefore', 'notAfter', 'CRL', 'OCSP']

# Lock for thread-safe file writing
file_lock = threading.Lock()

def get_extension_value(cert, ext_name):
    extension_count = cert.get_extension_count()
    for i in range(extension_count):
        ext = cert.get_extension(i)
        if ext.get_short_name().decode() == ext_name:
            cleaned_value = str(ext).replace('\n', ' ').replace('\r', ' ').strip()
            cleaned_value = ' '.join(cleaned_value.split())
            return cleaned_value
    return ""

def process_certificate(cert_file):
    try:
        with open(cert_file, "rb") as file:
            cert_data = file.read()
        if b"-----BEGIN CERTIFICATE-----" not in cert_data:
            print(f"Skipping invalid certificate file: {cert_file}")
            return None
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    except Exception as e:
        print(f"Error processing file {cert_file}: {e}")
        return None

    subject = cert.get_subject()
    issuer = cert.get_issuer()

    cert_info = {
        'serialnumber': format(cert.get_serial_number(), 'x').upper(),
        'subjectC': getattr(subject, 'C', ""),
        'subjectCN': getattr(subject, 'CN', ""),
        'subjectL': getattr(subject, 'L', ""),
        'subjectO': getattr(subject, 'O', ""),
        'subjectOU': getattr(subject, 'OU', ""),
        'issuerC': getattr(issuer, 'C', ""),
        'issuerCN': getattr(issuer, 'CN', ""),
        'issuerL': getattr(issuer, 'L', ""),
        'issuerO': getattr(issuer, 'O', ""),
        'issuerOU': getattr(issuer, 'OU', ""),
        'notBefore': cert.get_notBefore().decode(),
        'notAfter': cert.get_notAfter().decode(),
        'CRL': get_extension_value(cert, 'crlDistributionPoints'),
        'OCSP': get_extension_value(cert, 'authorityInfoAccess'),
    }
    return cert_info

def write_to_csv(cert_data):
    if cert_data is not None:
        with file_lock:
            with open(OUTPUT_FILE, 'a', newline='', encoding='utf-8') as file:
                writer = csv.DictWriter(file, fieldnames=CSV_HEADERS)
                writer.writerow(cert_data)

def main():
    # Prepare the output CSV file
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=CSV_HEADERS)
        writer.writeheader()

    # Setup ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
        for filename in os.listdir(FOLDER_PATH):
            full_path = os.path.join(FOLDER_PATH, filename)
            if os.path.isfile(full_path):
                executor.submit(write_to_csv, process_certificate(full_path))

main()
