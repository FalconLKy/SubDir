import argparse
import requests
import os
import urllib3
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from colorama import Fore, Style, init as colorama_init
import warnings
import dns.resolver
from collections import deque

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.simplefilter("ignore")
colorama_init(autoreset=True)

# Banner
SUBDIR_BANNER = f"""
{Fore.CYAN}  ____        _     _ _           
 / ___| _   _| |__ (_) |_ _   _   {Fore.YELLOW}SUBDIR
 \___ \| | | | '_ \| | __| | | |  {Fore.GREEN}by F4lc0n
  ___) | |_| | |_) | | |_| |_| |  {Fore.MAGENTA}https://github.com/FalconLKy
 |____/ \__,_|_.__/|_|\__|\__, |  
                         |___/   {Style.RESET_ALL}
"""

def banner():
    print(SUBDIR_BANNER)

# Passive subdomain enumeration

def get_subdomains_passive(domain):
    print(f"{Fore.BLUE}[*] Collecting subdomains passively...{Style.RESET_ALL}")
    sources = [crtsh_search, threatcrowd_search, waybackurls_search]
    subdomains = set()
    for source in sources:
        try:
            found = source(domain)
            subdomains.update(found)
        except Exception as e:
            print(f"{Fore.RED}[!] Error in {source.__name__}: {e}{Style.RESET_ALL}")
    return sorted(subdomains)

def crtsh_search(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = requests.get(url, timeout=10)
    entries = resp.json()
    return set(entry['name_value'] for entry in entries if domain in entry['name_value'])

def threatcrowd_search(domain):
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    resp = requests.get(url, timeout=10)
    data = resp.json()
    return set(data.get('subdomains', []))

def waybackurls_search(domain):
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=text&fl=original&collapse=urlkey"
    resp = requests.get(url, timeout=10)
    subdomains = set()
    for line in resp.text.splitlines():
        parts = line.split('/')[2]
        if domain in parts:
            subdomains.add(parts)
    return subdomains

# Active subdomain brute-force via DNS

def brute_force_subdomains(domain, wordlist, threads, stealth):
    print(f"{Fore.BLUE}[*] Brute-forcing subdomains...{Style.RESET_ALL}")
    with open(wordlist, 'r') as f:
        prefixes = [line.strip() for line in f if line.strip()]

    resolver = dns.resolver.Resolver()
    found = set()

    def check_sub(prefix):
        full_domain = f"{prefix}.{domain}"
        try:
            resolver.resolve(full_domain, 'A', lifetime=3)
            return full_domain
        except:
            return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_sub, p) for p in prefixes]
        for f in tqdm(futures, desc="Subdomains", ncols=70):
            res = f.result()
            if res:
                found.add(res)
    return sorted(found)

# Alive HTTP scan

def check_alive(subdomains, codes_filter, stealth, threads, user_agent):
    print(f"{Fore.BLUE}[*] Performing alive scan...{Style.RESET_ALL}")
    headers = {"User-Agent": user_agent or "Mozilla/5.0"}

    alive = []
    def check(domain):
        url = f"https://{domain}"
        try:
            r = requests.get(url, headers=headers, timeout=5, verify=False)
            if not codes_filter or r.status_code in codes_filter:
                return (domain, r.status_code)
        except:
            return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check, d) for d in subdomains]
        for f in tqdm(futures, desc="Alive", ncols=70):
            res = f.result()
            if res:
                alive.append(res)

    for dom, code in alive:
        print(f"{Fore.GREEN}[+] {dom} [{code}]{Style.RESET_ALL}")
    return alive

# Passive directory enumeration via Wayback

def passive_dirs(domain):
    print(f"{Fore.BLUE}[*] Collecting directories passively (Wayback)...{Style.RESET_ALL}")
    dirs = set()
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if domain in line:
                    path = '/' + '/'.join(line.split('/')[3:])
                    if path and '.' not in path.split('/')[-1]:
                        dirs.add(path.split('?')[0].split('#')[0])
    except Exception as e:
        print(f"{Fore.RED}[!] Passive dir error: {e}{Style.RESET_ALL}")
    return sorted(dirs)

# Active directory brute-force with BFS

def active_dirs(domain, wordlist, threads, stealth, max_depth):
    print(f"{Fore.BLUE}[*] Brute-forcing directories...{Style.RESET_ALL}")
    if not os.path.isfile(wordlist):
        print(f"{Fore.RED}[!] Wordlist not found: {wordlist}{Style.RESET_ALL}")
        return []
    with open(wordlist, 'r') as f:
        paths = [line.strip() for line in f if line.strip()]

    headers = {"User-Agent": "Mozilla/5.0"}
    results = []
    visited = set()
    queue = deque([f"https://{domain}"])

    while queue:
        current = queue.popleft()
        depth = current.count('/') - 2
        if depth >= max_depth:
            continue
        for p in paths:
            url = f"{current}/{p.strip('/')}"
            if url in visited:
                continue
            visited.add(url)
            try:
                r = requests.get(url, headers=headers, timeout=5, verify=False)
                if r.status_code < 400:
                    results.append((url, r.status_code))
                    queue.append(url)
            except:
                pass
    return results

# Main entry point

def main():
    parser = argparse.ArgumentParser(prog='subdir', description='Subdir: passive & active recon tool')
    parser.add_argument('-t', '--target', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--sub', action='store_true', help='Run subdomain enumeration')
    parser.add_argument('--dir', action='store_true', help='Run directory enumeration')
    parser.add_argument('--all', action='store_true', help='Run both subdomain and directory enumeration')
    parser.add_argument('-m', '--mode', choices=['passive', 'active', 'both'], default='passive', help='Subdomain mode')
    parser.add_argument('--dir-mode', choices=['passive', 'active', 'both', 'none'], default='none', help='Directory mode')
    parser.add_argument('-w', '--wordlist', help='Wordlist for brute-force')
    parser.add_argument('-T', '--threads', type=int, default=50, help='Number of threads for scans')
    parser.add_argument('-c', '--codes', help='Filter HTTP codes (e.g., 200,403)')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--user-agent', help='Custom User-Agent header')
    parser.add_argument('--proxy', '-P', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--depth', type=int, default=2, help='Max directory recursion depth')
    args = parser.parse_args()

    banner()

    # Configure proxy
    if args.proxy:
        sess = requests.Session()
        sess.proxies.update({'http': args.proxy, 'https': args.proxy})
        requests.get = sess.get

    subdomains = []
    dirs_found = []

    if args.all or args.sub:
        if args.mode in ['passive', 'both']:
            subdomains += get_subdomains_passive(args.target)
        if args.mode in ['active', 'both'] and args.wordlist:
            subdomains += brute_force_subdomains(args.target, args.wordlist, args.threads, args.stealth)

        subdomains = sorted(set(subdomains))
        print(f"{Fore.YELLOW}[+] Found {len(subdomains)} subdomains{Style.RESET_ALL}")
        codes_filter = set(map(int, args.codes.split(','))) if args.codes else set()
        alive_results = check_alive(subdomains, codes_filter, args.stealth, args.threads, args.user_agent)

    if args.all or args.dir:
        print(f"\n{Fore.CYAN}[+] Starting directory enumeration...{Style.RESET_ALL}")
        if args.dir_mode in ['passive', 'both']:
            pd = passive_dirs(args.target)
            for d in pd:
                print(f"{Fore.GREEN}- https://{args.target}{d}{Style.RESET_ALL}")
                dirs_found.append((f"https://{args.target}{d}", 'passive'))
        if args.dir_mode in ['active', 'both'] and args.wordlist:
            ad = active_dirs(args.target, args.wordlist, args.threads, args.stealth, args.depth)
            for url, code in ad:
                print(f"{Fore.GREEN}- {url} [{code}]{Style.RESET_ALL}")
                dirs_found.append((url, code))

    if args.output:
        with open(args.output, 'w') as f:
            if args.all or args.sub:
                f.write("# Alive Subdomains:\n")
                for domain, code in alive_results:
                    f.write(f"{domain} [{code}]\n")
            if args.all or args.dir:
                f.write("\n# Enumerated Directories:\n")
                for url, code in dirs_found:
                    f.write(f"{url} [{code}]\n")

if __name__ == '__main__':
    main()
