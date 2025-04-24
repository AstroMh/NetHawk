#!/usr/bin/env python

from termcolor import colored
import time
import os
import sys

try:
	from src.core.menu import Menu
	from src.utils.dependency_checker import check_all_dependencies
except ImportError as e:
	print(colored(f"[!] Error importing required modules: {str(e)}", 'red'))
	print(colored("[!] Make sure you have installed all dependencies with 'pip install -r requirements.txt'", 'yellow'))
	sys.exit(1)

class NetHawk:
	def __init__(self):
		# Check if essential dependencies are available
		dependencies = check_all_dependencies()
		
		if not dependencies["core"]["scapy"]:
			print(colored("[!] Scapy is required for most features of NetHawk. Please install it.", 'red'))
			sys.exit(1)
			
		try:
			while True:
				Menu()
		except KeyboardInterrupt:
			print("\n\n" + colored("[!] CTRL + C Detected. Exiting the program.\n", "red"))

if __name__ == "__main__":
	NetHawk()
		 		
