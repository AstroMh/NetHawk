#!/usr/bin/env python

import scapy.all as scapy
import argparse as ap
from src.logos.logo import Logo
from termcolor import colored

class NetScanner:
    def __init__(self, target):
        logo = Logo()
        logo.net_scanner_logo()
        scan_results = self.scan(target)
        self.print_results(scan_results)
        yes_no = input(colored("\n[?] Do you want to save the output to a file (y/n)? ", 'yellow'))
        if yes_no.lower() == "y":
            self.write_file(scan_results)
        input(colored("\n\n[+] Scan successfully finished. Press ENTER to return to main menu.", 'green', attrs=["blink"]))
        
    def scan(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        clients_list = []
        for i in answered_list:
            clients_dict = {"ip":i[1].psrc, "mac":i[1].hwsrc}
            clients_list.append(clients_dict)
        return clients_list
        
    def write_file(self, results):
        with open("scan_results.txt", "w") as file:
            for i in results:
                file.write("IP: " + str(i['ip']) + ", MAC: " + str(i['mac']) + "\n")

    def print_results(self, results_list):
        print(colored("\nIP\t\t\tMAC Address", 'cyan', attrs=['bold']))
        print(colored("-----------------------------------------", 'cyan'))
        for client in results_list:
            print(colored("[+] ", 'green') + client["ip"] + "\t\t" + colored(client["mac"], 'cyan')) 