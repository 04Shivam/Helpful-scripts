import os
import argparse
import subprocess
import requests
import socket
import csv
from urllib.parse import urlparse

def subfinder(domain):
    try:
        result = subprocess.run(["subfinder", "-d", domain], check=True, capture_output=True, text=True)
        return result.stdout.strip().splitlines()
    except subprocess.CalledProcessError as e:
        print(f"[!] subfinder failed: {e}")
        return []

def assetfinder(domain):
    try:
        result = subprocess.run(["assetfinder", domain], check=True, capture_output=True, text=True)
        return result.stdout.strip().splitlines()
    except subprocess.CalledProcessError as e:
        print(f"[!] assetfinder failed: {e}")
        return []

def parse_crt_sh(json_data):
    subdomains_found = set()
    for d in json_data:
        domain_names = d.get("name_value", "").strip().split("\n")
        for domain_name in domain_names:
            domain_name = domain_name.strip()
            if domain_name.startswith("*"):
                domain_name = ".".join(domain_name.split(".")[1:])
            subdomains_found.add(domain_name)
    return list(subdomains_found)

def crtsh(domain):
    url = f"https://crt.sh/json?q={domain}"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return parse_crt_sh(response.json())
    except requests.RequestException as e:
        print(f"[!] crt.sh request failed: {e}")
        return []

def probe_live_domains(subdomains):
    try:
        process = subprocess.Popen(
            ["httprobe", "-prefer-https"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        stdout, _ = process.communicate("\n".join(subdomains))
        return stdout.strip().splitlines()
    except Exception as e:
        print(f"[!] Error during probing: {e}")
        return []

def resolve_ip_addresses(domains):
    ip_map = {}
    for domain in domains:
        try:
            ip_list = list(set(socket.gethostbyname_ex(domain)[2]))
            ip_map[domain] = ip_list
        except socket.gaierror:
            ip_map[domain] = []
    return ip_map

def map_urls_to_subdomains(urls):
    url_map = {}
    for url in urls:
        try:
            hostname = urlparse(url).hostname
            if hostname:
                url_map[hostname] = url
        except Exception:
            continue
    return url_map

def save_to_file(filename, data):
    with open(filename, "w") as f:
        for line in sorted(data):
            f.write(f"{line}\n")

def save_ip_map(filename, ip_map):
    with open(filename, "w") as f:
        for domain, ips in sorted(ip_map.items()):
            ip_str = ", ".join(ips) if ips else "No IP found"
            f.write(f"{domain}: {ip_str}\n")

def save_to_csv(filename, subdomains, ip_map, url_map):
    with open(filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["Subdomain", "IP Addresses", "URL", "Page Info"])
        writer.writeheader()

        for subdomain in sorted(subdomains):
            ips = ", ".join(ip_map.get(subdomain, []))
            url = url_map.get(subdomain, "")
            writer.writerow({
                "Subdomain": subdomain,
                "IP Addresses": ips,
                "URL": url,
                "Page Info": "",
                "Running IP": ""
            })

def main():
    parser = argparse.ArgumentParser(description="Enumerate subdomains and resolve IPs.")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to enumerate")
    args = parser.parse_args()

    domain = args.domain
    data_dir = "data"
    os.makedirs(data_dir, exist_ok=True)

    print(f"[*] Enumerating subdomains for: {domain}")
    subdomains = set()
    subdomains.update(subfinder(domain))
    subdomains.update(assetfinder(domain))
    subdomains.update(crtsh(domain))

    print(f"[+] Total unique subdomains found: {len(subdomains)}")
    subdomain_file = os.path.join(data_dir, f"{domain}_subdomains.txt")
    save_to_file(subdomain_file, subdomains)
    print(f"[+] Subdomains saved to: {subdomain_file}")

    print(f"[*] Probing for live domains...")
    live_domains = probe_live_domains(subdomains)
    print(f"[+] Total live domains: {len(live_domains)}")
    live_file = os.path.join(data_dir, f"{domain}_live_domains.txt")
    save_to_file(live_file, live_domains)
    print(f"[+] Live domains saved to: {live_file}")

    print(f"[*] Resolving IP addresses...")
    ip_map = resolve_ip_addresses(subdomains)
    ip_file = os.path.join(data_dir, f"{domain}_ips.txt")
    save_ip_map(ip_file, ip_map)
    print(f"[+] IP addresses saved to: {ip_file}")
    
    url_map = map_urls_to_subdomains(live_domains)
    csv_file = os.path.join(data_dir, f"{domain}_results.csv")
    save_to_csv(csv_file, subdomains, ip_map, url_map)
    print(f"[+] CSV saved to: {csv_file}")


if __name__ == "__main__":
    main()
