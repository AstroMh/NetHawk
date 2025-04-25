from termcolor import colored
import time
import re
import os
import socket
import sys

try:
    import keyboard
    KEYBOARD_AVAILABLE = True
except ImportError:
    KEYBOARD_AVAILABLE = False

from src.utils.dependency_checker import check_dependency
from src.logos.logo import Logo

# Import tools conditionally
def import_listener():
    if check_dependency("src.tools.listener", ""):
        from src.tools.listener import Listener
        return Listener
    return None

def import_Torchain():
    if check_dependency("src.tools.TorChain", ""):
        from src.tools.TorChain import TorProxyChain
        return TorProxyChain
    return None

def import_packetsniff():
    if check_dependency("src.tools.packetsniff", ""):
        from src.tools.packetsniff import Sniffer
        return Sniffer
    return None

def import_code_injector():
    if check_dependency("src.tools.code_injector", ""):
        from src.tools.code_injector import CodeInjector
        return CodeInjector
    return None

def import_arpspoof():
    if check_dependency("src.tools.arpspoof", ""):
        from src.tools.arpspoof import ARPSpoof
        return ARPSpoof
    return None

def import_netscan():
    if check_dependency("src.tools.netscan", ""):
        from src.tools.netscan import NetScanner
        return NetScanner
    return None

def import_webscan():
    if check_dependency("src.tools.webscan", ""):
        from src.tools.webscan import WebScanner
        return WebScanner
    return None

class Menu:
    """Class to initiate which sub-program is called by checking the input"""
    def __init__(self):
        os.system('clear')
        logo = Logo()
        logo.toolkit_logo()
        # Sub programs
        action_list = ["Backdoor listener", "Code Injector", "Packet Sniffer", "ARP Spoofer",
                       "Network Scanner", "Web Scanner", "TorChain", "Exit"]
        for i in range(0, len(action_list)):
            print(colored("[{}]".format(i+1), 'yellow') + " {}".format(action_list[i]))
            time.sleep(0.2)
            
        action = input(colored("\n\n[-] ", 'magenta') + colored("Enter an action: ", 'cyan', attrs=['bold']))
        action = action.split(' ')
        self.check_input(action)

    # Get the ip address of your system
    def get_system_ip(self):
        # This method might have some issues
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            # trying to connect to a remote server in order to get the ip address
            # of this machine
            s.connect(('10.254.254.254', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    # IP validation method
    def valid_ip(self, ip):
        pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip))

    # Checking the input in order to call the right program
    def check_input(self, action):
        if action[0] == "1":
            Listener = import_listener()
            if not Listener:
                input(colored("\nPress Enter to return to the main menu...", 'cyan'))
                return
                
            if not KEYBOARD_AVAILABLE:
                print(colored("[!] The keyboard module is not available.", 'red'))
                print(colored("[!] Some features of the Backdoor listener may not work properly.", 'yellow'))
                print(colored("[!] Please install it with: 'pip install keyboard'", 'yellow'))
                ip_address = input(colored("[-]", 'blue') + " Set your IP Address: ")
                if self.valid_ip(ip_address):
                    self.open_listener(ip_address, Listener)
                else:
                    print(colored("[!] Invalid IP input.", 'red'))
                    time.sleep(2)
            else:
                print(colored("[-] ", 'yellow') + "Press UP Arrow to set IP! Press Down Arrow to set IP manually!")
                while True:
                    if keyboard.is_pressed('up'):
                        # This condition might have some problems, fixing it in the coming updates
                        ip_address = self.get_system_ip()
                        if self.valid_ip(ip_address):
                            self.open_listener(ip_address, Listener)
                        else:
                            print(colored("[!] Invalid IP input.", 'red'))
                            time.sleep(2)
                    elif keyboard.is_pressed('down'):
                        ip_address = input(colored("[-]", 'blue') + " Set your IP Address: ")
                        if self.valid_ip(ip_address):
                            self.open_listener(ip_address, Listener)
                        else:
                            print(colored("[!] Invalid IP input.", 'red'))
                            time.sleep(2)
                            break
                
        elif action[0] == "2":
            CodeInjector = import_code_injector()
            if CodeInjector:
                CodeInjector()
            else:
                input(colored("\nPress Enter to return to the main menu...", 'cyan'))
                
        elif action[0] == "3":
            Sniffer = import_packetsniff()
            if not Sniffer:
                input(colored("\nPress Enter to return to the main menu...", 'cyan'))
                return
                
            interface = input(colored("[-]", 'blue') + " Set your interface to sniff on: ")
            if KEYBOARD_AVAILABLE:
                keyboard.read_key()
            Sniffer(interface)
            
        elif action[0] == "4":
            ARPSpoof = import_arpspoof()
            if not ARPSpoof:
                input(colored("\nPress Enter to return to the main menu...", 'cyan'))
                return
                
            target_ip = input(colored("[?] ", 'magenta') + "Enter your target's IP Address: ")
            AP_IP = input(colored("[?] ", 'magenta') + "Enter your Access Point IP Address: ")
            if self.valid_ip(target_ip) and self.valid_ip(AP_IP):
                ARPSpoof(target_ip, AP_IP)
            else:
                print(colored("[!] Invalid IP input.", 'red'))
                time.sleep(2)
                
        elif action[0] == "5":
            NetScanner = import_netscan()
            if not NetScanner:
                input(colored("\nPress Enter to return to the main menu...", 'cyan'))
                return
                
            ip_range = input(colored("[?] Set your IP (IP range): ", 'yellow'))
            NetScanner(ip_range)
            
        elif action[0] == "6":
            WebScanner = import_webscan()
            if not WebScanner:
                input(colored("\nPress Enter to return to the main menu...", 'cyan'))
                return
                
            target_url = input(colored("[?] ", 'magenta') + "Enter the target URL (e.g., https://example.com): ")
            if not target_url.startswith("http"):
                target_url = "http://" + target_url
                
            print(colored("[*] ", 'blue') + "Setting up web scanner options...")
            max_threads = 10
            timeout = 5
            verbose = False
            
            try:
                max_threads = int(input(colored("[?] ", 'yellow') + f"Enter max threads (default: {max_threads}): ") or max_threads)
                timeout = int(input(colored("[?] ", 'yellow') + f"Enter timeout in seconds (default: {timeout}): ") or timeout)
                verbose_input = input(colored("[?] ", 'yellow') + "Enable verbose output? (y/n): ").lower()
                verbose = verbose_input == 'y'
                
                scanner = WebScanner(target_url, max_threads, timeout, verbose)
                
                report_format = input(colored("[?] ", 'cyan') + "Choose report format (json/html/csv) [default: html]: ").lower() or "html"
                if report_format not in ["json", "html", "csv"]:
                    print(colored("[!] ", 'yellow') + "Invalid format, using HTML as default")
                    report_format = "html"
                    
                scanner.run(report_format)
                input(colored("\nPress Enter to return to the main menu...", 'cyan'))
            except Exception as e:
                print(colored(f"[!] Error: {str(e)}", 'red'))
                input(colored("\nPress Enter to return to the main menu...", 'cyan'))

        elif action[0] == "7":
            print(colored("\n[!] Running Tor Proxy Chain...", 'yellow'))
            TorProxy = import_Torchain()
            if not TorProxy:
                input(colored("\nPress Enter to return to the main menu...", 'cyan'))
                return
            
        elif action[0] == "8":
            print(colored("\n[*] Exiting the Program.", 'red'))
            time.sleep(1)
            os.system('clear')
            sys.exit(0)
            
        else:
            print(colored("\n[!] Action not found. Please Enter the correct number...", 'yellow', attrs=["bold"]))
            time.sleep(3)
    
    # Opening listener for the Backdoor
    def open_listener(self, ip, Listener):
        my_listener = Listener(ip, 4444)
        while True:
            my_listener.run() 