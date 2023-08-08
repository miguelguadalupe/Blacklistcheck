import requests
from colorama import init, Fore, Style

init()  # Initialize colorama

def check_ip_abuseipdb(ip_address, api_key):
    url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        result = response.json()

        if result['data']['totalReports'] > 0:
            print(f"{Fore.RED}AbuseIPDB:")
            print(f"    The IP address {ip_address} has been reported {result['data']['totalReports']} times.")
            print(f"    Confidence level: {result['data']['abuseConfidenceScore']}/100")
        else:
            print(f"{Fore.GREEN}AbuseIPDB:")
            print(f"    The IP address {ip_address} has not been reported.")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}An error occurred while checking the IP address with AbuseIPDB: {e}")

    print(Style.RESET_ALL)  # Reset colorama style


def check_ip_virustotal(ip_address, api_key):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {
        'x-apikey': api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()
        
        if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print(f"{Fore.RED}VirusTotal:")
            print(f"    The IP address {ip_address} is considered malicious.")
        else:
            print(f"{Fore.GREEN}VirusTotal:")
            print(f"    The IP address {ip_address} is not considered malicious.")
        
        malicious_count = result['data']['attributes']['last_analysis_stats']['malicious']
        vendors_count = malicious_count + result['data']['attributes']['last_analysis_stats']['suspicious']
        
        print(f"    It is flagged by {malicious_count} vendors as malicious.")
        print(f"    It is flagged by a total of {vendors_count} vendors.")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}An error occurred while checking the IP address with VirusTotal: {e}")

    print(Style.RESET_ALL)  # Reset colorama style


# Set your AbuseIPDB API key here
ABUSEIPDB_API_KEY = 'Your_Key_Here'

# Set your VirusTotal API key here
VIRUSTOTAL_API_KEY = 'Your_Key_Here'

# Prompt the user to enter the IP address
ip_address = input("Enter the IP address to check: ")

print ()

check_ip_abuseipdb(ip_address, ABUSEIPDB_API_KEY)
check_ip_virustotal(ip_address, VIRUSTOTAL_API_KEY)
