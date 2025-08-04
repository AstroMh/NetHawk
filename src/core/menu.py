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
    """Import the WebScanner class from the webscan module"""
    try:
        # Verify the project structure
        import subprocess
        import os
        
        # Find the path to the verification script
        try:
            from src.tools.webscan import __file__ as webscan_init_file
            check_script = os.path.join(os.path.dirname(webscan_init_file), "check_structure.py")
            
            # Run the verification script
            if os.path.isfile(check_script):
                result = subprocess.run(["python", check_script], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE,
                                        text=True)
                if result.returncode != 0:
                    print(colored("\n[!] ", 'red') + "Webscan module structure verification failed.")
                    print(result.stdout)
                    return None
        except Exception as e:
            print(colored("\n[!] ", 'yellow') + f"Could not run structure verification: {str(e)}")
        
        # Try to import the WebScanner class
        try:
            from src.tools.webscan import WebScanner, check_webscan_requirements
            
            # If WebScanner is None, it means it couldn't be imported correctly
            if WebScanner is None:
                print(colored("\n[!] ", 'red') + "Could not import WebScanner module.")
                print(colored("[!] ", 'yellow') + "Make sure all required files are present.")
                return None
            
            # Check web scanner requirements
            if not check_webscan_requirements():
                print(colored("\n[!] ", 'yellow') + "Some requirements for running the web scanner are missing.")
                print(colored("[!] ", 'yellow') + "Please install all required dependencies.")
                return None
            
            return WebScanner
        except ImportError as e:
            print(colored("\n[!] ", 'red') + f"Error importing WebScanner: {str(e)}")
            print(colored("[!] ", 'yellow') + "Make sure the project structure is correct.")
            return None
    except Exception as e:
        print(colored("\n[!] ", 'red') + f"Unexpected error: {str(e)}")
        print(colored("[!] ", 'yellow') + "This feature requires the webscan module to be correctly installed.")
        return None

class Menu:
    """Class to initiate which sub-program is called by checking the input"""
    def __init__(self):
        os.system('clear')
        logo = Logo()
        logo.toolkit_logo()
        # Sub programs
        action_list = ["Backdoor listener", "Code Injector", "Packet Sniffer", "ARP Spoofer", "Network Scanner", "Web Scanner", "Exit"]
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
                
            try:
                target_url = input(colored("[?] ", 'magenta') + "Enter the target URL (e.g., https://example.com): ")
                if not target_url:
                    print(colored("[!] ", 'red') + "Invalid URL. Returning to main menu.")
                    input(colored("\nPress Enter to return to the main menu...", 'cyan'))
                    return
                    
                if not target_url.startswith("http"):
                    target_url = "http://" + target_url
                    
                print(colored("[*] ", 'blue') + "Setting up web scanner options...")
                max_threads = 10
                timeout = 5
                verbose = False
                db_uri = None
                
                try:
                    max_threads_input = input(colored("[?] ", 'yellow') + f"Enter max threads (default: {max_threads}): ")
                    if max_threads_input.strip():
                        max_threads = int(max_threads_input)
                        
                    timeout_input = input(colored("[?] ", 'yellow') + f"Enter timeout in seconds (default: {timeout}): ")
                    if timeout_input.strip():
                        timeout = int(timeout_input)
                        
                    verbose_input = input(colored("[?] ", 'yellow') + "Enable verbose output? (y/n): ").lower()
                    verbose = verbose_input == 'y'
                    
                    db_input = input(colored("[?] ", 'yellow') + "Use database connection? (y/n): ").lower()
                    if db_input == 'y':
                        db_uri = input(colored("[?] ", 'yellow') + "Enter PostgreSQL connection URI (postgresql://username:password@host:port/dbname): ")
                        if not db_uri or not db_uri.startswith('postgresql://'):
                            print(colored("[!] ", 'yellow') + "Invalid PostgreSQL URI format. Using default connection settings.")
                            db_uri = 'postgresql://postgres:postgres@localhost:5432/nethawk'
                    
                    print(colored("\n[*] ", 'blue') + "Initializing web scanner...")
                    print(colored("[*] ", 'blue') + f"Target URL: {target_url}")
                    print(colored("[*] ", 'blue') + f"Max Threads: {max_threads}")
                    print(colored("[*] ", 'blue') + f"Timeout: {timeout} seconds")
                    print(colored("[*] ", 'blue') + f"Verbose: {'Yes' if verbose else 'No'}")
                    print(colored("[*] ", 'blue') + f"Database: {'Yes' if db_uri else 'No'}")
                    
                    try:
                        scanner = WebScanner(target_url, max_threads, timeout, verbose, db_uri)
                        
                        report_format = input(colored("[?] ", 'cyan') + "Choose report format (json/html/csv) [default: html]: ").lower() or "html"
                        if report_format not in ["json", "html", "csv"]:
                            print(colored("[!] ", 'yellow') + "Invalid format, using HTML as default")
                            report_format = "html"
                            
                        print(colored("\n[+] ", 'green') + "Starting web scan...")
                        scanner.run(report_format)
                        print(colored("\n[+] ", 'green') + "Web scan completed successfully!")
                    except Exception as e:
                        print(colored(f"\n[!] Error during scan: {str(e)}", 'red'))
                        print(colored("[!] ", 'yellow') + "The scan could not be completed.")
                        
                except ValueError as e:
                    print(colored(f"\n[!] Invalid input: {str(e)}", 'red'))
            except Exception as e:
                print(colored(f"\n[!] Unexpected error: {str(e)}", 'red'))
            
            input(colored("\nPress Enter to return to the main menu...", 'cyan'))
            
        elif action[0] == "7":
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