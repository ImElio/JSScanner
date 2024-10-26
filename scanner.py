import requests
import re
import argparse
import json
import signal
import sys
import os
import colorama
from colorama import Fore, Style
from pystyle import Center, Colors, Colorate
import platform

colorama.init(autoreset=True)

banner = r"""
  ____
 / ___|  ___ __ _ _ __  _ __   ___ _ __
 \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  ___) | (_| (_| | | | | | | |  __/ |
 |____/ \___\__,_|_| |_|_| |_|\___|_|

✔ Creator: Elio(TOOL Developer)
✔ Collaborator: NotKronoos(Front-End)
"""

print(Colorate.Diagonal(Colors.purple_to_red, banner))


def find_links_in_js(content):
    regex = r'(https?://[^\s\'"<>]+)'
    return re.findall(regex, content)


## Pattern by (https://github.com/fa-rrel)
def uncover_secrets(content):
    patterns = {
        'AWS Access Key': r'(?i)AWS_Access_Key\s*:\s*[\'"]?([A-Z0-9]{20})[\'"]?',
        'AWS Secret Key': r'(?i)AWS_Secret_Key\s*:\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
        'Stripe Secret Key': r'(?i)Stripe_Secret_Key\s*:\s*[\'"]?([A-Za-z0-9]{24})[\'"]?',
        'GitHub Token': r'(?i)GitHub Token\s*:\s*[\'"]?([A-Za-z0-9]{36})[\'"]?',
        'Facebook Token': r'(?i)Facebook_Token\s*:\s*[\'"]?([A-Za-z0-9\.]+)[\'"]?',
        'Telegram Bot Token': r'(?i)Telegram Bot Token\s*:\s*[\'"]?([A-Za-z0-9:]+)[\'"]?',
        'Google Maps API Key': r'(?i)Google Maps API Key\s*:\s*[\'"]?([A-Za-z0-9_-]+)[\'"]?',
        'Google reCAPTCHA Key': r'(?i)Google reCAPTCHA Key\s*:\s*[\'"]?([A-Za-z0-9_-]+)[\'"]?',
        'API Key': r'(?i)API_Key\s*:\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
        'Secret Key': r'(?i)Secret_Key\s*:\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
        'Auth Domain': r'(?i)Auth_Domain\s*:\s*[\'"]?([A-Za-z0-9\-]+\.[a-z]{2,})[\'"]?',
        'Database URL': r'(?i)Database_URL\s*:\s*[\'"]?([^\'" ]+)[\'"]?',
        'Storage Bucket': r'(?i)Storage_Bucket\s*:\s*[\'"]?([^\'" ]+)[\'"]?',
        'Cloud Storage API Key': r'(?i)Cloud Storage API Key\s*:\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?'
    }

    found_items = {}
    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            found_items[name] = list(set(matches))

    object_pattern = r'(?i)const\s+[A-Z_]+_KEYS\s*=\s*\{([^}]+)\}'
    object_matches = re.findall(object_pattern, content)

    for match in object_matches:
        for line in match.split(','):
            line = line.strip()
            for name in patterns.keys():
                if name.lower().replace(' ', '_') in line.lower():
                    value = re.search(r'\:\s*[\'"]?([^\'", ]+)[\'"]?', line)
                    if value:
                        found_items[name] = found_items.get(name, []) + [value.group(1)]

    return found_items


def signal_handler(sig, frame):
    response = input(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Do you wish to exit? (Y/N): ").strip().lower()
    if response == 'y':
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Exiting... Goodbye!")
        sys.exit(0)
    else:
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Resuming operation...")


def run_extraction(input_file, output_file, find_secrets, find_urls, specific_url):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(banner)

    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    js_urls = []
    if specific_url:
        js_urls.append(specific_url)
    else:
        with open(input_file, 'r') as f:
            js_urls = f.readlines()

    collected_links = []
    discovered_secrets = {}

    for js_url in js_urls:
        js_url = js_url.strip()
        if not js_url:
            continue

        try:
            response = requests.get(js_url, verify=False)
            response.raise_for_status()

            if find_urls:
                links = find_links_in_js(response.text)
                collected_links.extend(links)
                print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {Fore.YELLOW}Found {len(links)} links in {js_url}{Style.RESET_ALL}")

                for link in links:
                    print(f"{Fore.GREEN}[+] {link}{Style.RESET_ALL}")
                if not links:
                    print(f"{Fore.RED}[INFO]{Style.RESET_ALL} {Fore.YELLOW}No URLs detected in {js_url}{Style.RESET_ALL}")

            if find_secrets:
                secrets = uncover_secrets(response.text)
                if secrets:
                    discovered_secrets[js_url] = secrets
                    print(f"{Fore.GREEN}[+] Secrets identified in {js_url}: {json.dumps(secrets, indent=2)}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[INFO]{Style.RESET_ALL} {Fore.YELLOW}No secrets identified in {js_url}{Style.RESET_ALL}")

        except requests.exceptions.SSLError as ssl_err:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} SSL error when accessing {js_url}: {str(ssl_err)}")
        except requests.RequestException as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Unable to fetch {js_url}: {str(e)}")

    if collected_links and find_urls:
        with open(output_file, 'w') as out_file:
            for link in collected_links:
                out_file.write(link + '\n')
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {Fore.YELLOW}Links have been saved to {output_file}{Style.RESET_ALL}")

    if discovered_secrets and find_secrets:
        secrets_output_file = output_file.replace('.txt', '_secrets.json')
        with open(secrets_output_file, 'w') as secrets_file:
            json.dump(discovered_secrets, secrets_file, indent=2)
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {Fore.YELLOW}Secrets have been saved to {secrets_output_file}{Style.RESET_ALL}")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    if platform.system() != 'Windows':
        signal.signal(signal.SIGTSTP, signal_handler)

    parser = argparse.ArgumentParser(description='Extract links and secrets from JavaScript files.')
    parser.add_argument('input_file', nargs='?', help='File containing JavaScript links')
    parser.add_argument('-o', '--output_file', default='extracted_links.txt', help='File to save extracted links')
    parser.add_argument('-u', '--url', help='Single JavaScript URL to fetch')
    parser.add_argument('--secrets', action='store_true', help='Look for secrets in JavaScript content')
    parser.add_argument('--urls', action='store_true', help='Extract URLs from JavaScript content')
    args = parser.parse_args()

    if not args.input_file and not args.url:
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {Fore.YELLOW} Please provide either an input file or a single URL.{Style.RESET_ALL}")
        sys.exit(1)
    if args.url and args.input_file:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Please provide either an input file or a single URL, not both.")
        sys.exit(1)

    run_extraction(args.input_file, args.output_file, args.secrets, args.urls, args.url)

