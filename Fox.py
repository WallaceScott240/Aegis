import socket
import threading
import requests
import paramiko
import os
import queue
import time
from concurrent.futures import ThreadPoolExecutor

# =====================
# CONSTANTS & CONFIG
# =====================
MAX_PORT_THREADS = 50
MAX_DIR_THREADS = 20
REQUEST_TIMEOUT = 5
SSH_TIMEOUT = 3

# Dark mode ANSI colors
COLOR_HEADER = "\033[1;95m"  # Purple
COLOR_MENU = "\033[1;36m"    # Cyan
COLOR_INPUT = "\033[1;33m"   # Yellow
COLOR_SUCCESS = "\033[1;92m" # Green
COLOR_WARNING = "\033[1;93m" # Yellow
COLOR_FAIL = "\033[1;91m"    # Red
COLOR_INFO = "\033[1;94m"    # Blue
COLOR_RESET = "\033[0m"

# =====================
# UTILITY FUNCTIONS
# =====================
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    banner = rf"""
{COLOR_HEADER}
    █████╗ ███████╗ ██████╗ ██╗███████╗
   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
   ███████║█████╗  ██║  ███╗██║███████╗
   ██╔══██║██╔══╝  ██║   ██║██║╚════██║
   ██║  ██║███████╗╚██████╔╝██║███████║
   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
{COLOR_INFO}
   [ Greek Shield of Cybersecurity ]
{COLOR_RESET}
"""
    print(banner)

# =====================
# SCANNING TOOLS
# =====================
def port_scan_worker(target, port_queue, results):
    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((target, port)) == 0:
                    results.append(port)
                    try:
                        sock.send(b"GET / HTTP/1.1\r\n\r\n")
                        banner = sock.recv(1024).decode().strip()
                        print(f"{COLOR_SUCCESS}[+] Port {port} open - {banner[:50]}{COLOR_RESET}")
                    except:
                        print(f"{COLOR_SUCCESS}[+] Port {port} open{COLOR_RESET}")
            port_queue.task_done()
        except queue.Empty:
            break

def port_scanner(target, ports):
    port_queue = queue.Queue()
    open_ports = []
    
    for port in ports:
        port_queue.put(port)
        
    print(f"{COLOR_INFO}\n[+] Scanning {len(ports)} ports on {target}{COLOR_RESET}")
    
    threads = []
    for _ in range(min(MAX_PORT_THREADS, len(ports))):
        t = threading.Thread(target=port_scan_worker, args=(target, port_queue, open_ports))
        t.daemon = True
        t.start()
        threads.append(t)
        
    port_queue.join()
    print(f"{COLOR_INFO}\n[+] Scan complete! Open ports: {open_ports}{COLOR_RESET}")
    return open_ports

def ssh_bruteforce(target, username, password_list):
    print(f"{COLOR_INFO}\n[+] Starting SSH brute-force on {target} with user '{username}'{COLOR_RESET}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for password in password_list:
        pwd = password.strip()
        try:
            ssh.connect(target, username=username, password=pwd, timeout=SSH_TIMEOUT, banner_timeout=30)
            print(f"{COLOR_SUCCESS}[SUCCESS] Password found: {pwd}{COLOR_RESET}")
            ssh.close()
            return True
        except paramiko.AuthenticationException:
            print(f"{COLOR_FAIL}[FAILED] {pwd}{COLOR_RESET}", end='\r', flush=True)
        except Exception as e:
            print(f"{COLOR_WARNING}[ERROR] {e}{COLOR_RESET}")
    print(f"\n{COLOR_FAIL}[!] Password not found in list{COLOR_RESET}")
    return False

def dir_enum_worker(target_url, word_queue, found_dirs):
    while not word_queue.empty():
        try:
            word = word_queue.get_nowait()
            url = f"{target_url}/{word.strip()}"
            try:
                r = requests.get(url, timeout=REQUEST_TIMEOUT)
                if r.status_code == 200:
                    found_dirs.append(url)
                    print(f"{COLOR_SUCCESS}[FOUND] {url}{COLOR_RESET}")
            except requests.RequestException:
                pass
            word_queue.task_done()
        except queue.Empty:
            break

def dir_enum(target_url, wordlist):
    word_queue = queue.Queue()
    found_dirs = []
    
    for word in wordlist:
        word_queue.put(word)
        
    print(f"{COLOR_INFO}\n[+] Enumerating {len(wordlist)} directories at {target_url}{COLOR_RESET}")
    
    threads = []
    for _ in range(min(MAX_DIR_THREADS, len(wordlist))):
        t = threading.Thread(target=dir_enum_worker, args=(target_url, word_queue, found_dirs))
        t.daemon = True
        t.start()
        threads.append(t)
        
    word_queue.join()
    print(f"{COLOR_INFO}\n[+] Enumeration complete! Found {len(found_dirs)} directories{COLOR_RESET}")
    return found_dirs

def banner_grabber(host, port):
    try:
        with socket.socket() as sock:
            sock.settimeout(2)
            sock.connect((host, port))
            sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            banner = sock.recv(1024).decode().strip()
            print(f"{COLOR_SUCCESS}[BANNER] {host}:{port}\n{'-'*50}\n{banner}\n{'-'*50}{COLOR_RESET}")
    except:
        print(f"{COLOR_FAIL}[!] Could not grab banner from {host}:{port}{COLOR_RESET}")

# =====================
# MAIN MENU
# =====================
def main_menu():
    print_banner()
    print(f"""{COLOR_MENU}
    1. Port Scanner
    2. SSH Brute Forcer
    3. Directory Enumerator
    4. Banner Grabber
    5. Exit
    {COLOR_RESET}""")
    return input(f"{COLOR_INPUT}Choose an option (1-5): {COLOR_RESET}")

def main():
    while True:
        choice = main_menu()
        
        if choice == "1":
            target = input(f"{COLOR_INPUT}Target IP/Hostname: {COLOR_RESET}")
            ports = list(map(int, input(f"{COLOR_INPUT}Ports to scan (comma-separated): {COLOR_RESET}").split(",")))
            port_scanner(target, ports)
            
        elif choice == "2":
            target = input(f"{COLOR_INPUT}Target IP (SSH): {COLOR_RESET}")
            username = input(f"{COLOR_INPUT}Username: {COLOR_RESET}")
            pwd_file = input(f"{COLOR_INPUT}Password list file path: {COLOR_RESET}")

            if os.path.exists(pwd_file):
                with open(pwd_file, 'r') as file:
                    password_list = file.readlines()
                ssh_bruteforce(target, username, password_list)
            else:
                print(f"{COLOR_FAIL}[ERROR] Password file not found!{COLOR_RESET}")
                
        elif choice == "3":
            url = input(f"{COLOR_INPUT}Target URL (e.g., http://example.com): {COLOR_RESET}")
            wordlist_file = input(f"{COLOR_INPUT}Wordlist file path: {COLOR_RESET}")

            if os.path.exists(wordlist_file):
                with open(wordlist_file, 'r') as file:
                    words = file.readlines()
                dir_enum(url, words)
            else:
                print(f"{COLOR_FAIL}[ERROR] Wordlist not found!{COLOR_RESET}")
                
        elif choice == "4":
            host = input(f"{COLOR_INPUT}Target IP/Hostname: {COLOR_RESET}")
            port = int(input(f"{COLOR_INPUT}Port: {COLOR_RESET}"))
            banner_grabber(host, port)
            
        elif choice == "5":
            print(f"{COLOR_INFO}Exiting Aegis...{COLOR_RESET}")
            break
            
        else:
            print(f"{COLOR_WARNING}Invalid choice. Please select 1-5{COLOR_RESET}")
        
        input(f"\n{COLOR_INPUT}Press Enter to continue...{COLOR_RESET}")

# =====================
# ENTRY POINT
# =====================
if __name__ == "__main__":
    main()