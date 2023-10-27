import nmap
import pytz
import requests
import socket
import os
import sys
import time
from datetime import datetime


green = "\033[32m"
white = "\033[0m"
cyan = "\033[36m"
yellow = "\033[33m"
pink = "\033[38;5;206m"
purple = "\033[35m"
blue = "\033[34m"
red = "\033[31m"
black = "\033[30m"
gray = "\033[90m"

os.system("clear")

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip, port))

        if result == 0:
            with open("port_open.txt", "a") as port_file:
                port_file.write(f"{ip} - Port {port} is open\n")
            return f"{green}Port {port} is open{white}"
        else:
            return f"{red}Port {port} is closed{white}"

    except socket.error:
        return f"{red}Failed to connect to Port {port}{white}"

def nmap_scan(ip):
    nmap_results = []
    for port in [80, 443, 22, 502, 1089, 11001, 1090, 1091, 1541, 2222, 3480, 4000, 5052]:
        result = scan_port(ip, port)
        nmap_results.append(f"{ip} - {result}")

    scanner = nmap.PortScanner()
    nmap_args = f"-v -p 80,443,22,502 --script scada-vulns --script-args vulns.scada.ports=502 -T4 -F"

    try:
        scanner.scan(ip, arguments=nmap_args)
        for host in scanner.all_hosts():
            for port, data in scanner[host]['tcp'].items():
                state = data['state']
                nmap_results.append(f"{ip} - Port {port}/tcp: {state}")
    except nmap.PortScannerError as e:
        nmap_results.append(f"{ip} - Nmap error: {e}")

    return nmap_results

#WordPress login page
def wp_login(ip):
    wp_results = []
    now = datetime.now(pytz.timezone("Israel"))
    formatted_time = now.strftime("[%d.%m.%Y - %I:%M:%S%p]")

    url = f"http://{ip}/wp-login.php"
    try:
        response = requests.get(url)
    except requests.exceptions.RequestException as e:
        wp_results.append(f"{formatted_time} - {ip} > Request error: {e}")
        return wp_results

    if response.status_code == 200 and "wp-login" in response.text:
        wp_results.append(f"{formatted_time} - {green}{ip}{white} > {cyan}Found !{white}")
    else:
        wp_results.append(f"{formatted_time} - {green}{ip}{white} > {red}Not Found !{white}")

    return wp_results

# Function to read IP addresses from a file
def ip_addr(file_name):
    ip_list = []
    with open(file_name, 'r') as file:
        for line in file:
            ip_list.append(line.strip())
    return ip_list

def main():
    try:
        ip_file = 'ip_il.txt' #Change name of files from directory
        ip_list = ip_addr(ip_file)

        print(f"Total IP addresses to scan: {len(ip_list)}\n")

        with open("port_open.txt", "w") as port_open_file:
            for ip in ip_list:
                print(f">> {ip}")
                nmap_results = nmap_scan(ip)
                for result in nmap_results:
                    print(result)

        print("\nOur code will try to connect all the possibilities IP's from Israel")
        print(f"Trying... {len(ip_list)}")

        for ip in ip_list:
            wp_results = wp_login(ip)
            for result in wp_results:
                print(result)
    except KeyboardInterrupt:
        time.sleep(1)
        print("\nExit The Program")
        sys.exit(1)

if __name__ == "__main__":
    main()
