from termcolor import colored
from Listener import listener
from packetsniff import Sniffer
from code_injector import injector
import keyboard
import time
from menu import Menu
import os

class Main:
	def __init__(self):
		try:
			while True:
				Menu()
		except KeyboardInterrupt:
			print("\n\n" + colored("[!] CTRL + C Detected. Exiting the programm.\n", "red"))

if __name__=="__main__":
	Main()
		 		
