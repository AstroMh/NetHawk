#!/usr/bin/env python

from termcolor import colored
import time
import os

class Logo:
	def toolkit_logo(self):
		print(colored("*******************************************", 'green') 
		+ colored("Made By AstroMh", 'cyan', attrs=['blink']) + colored("*********************************************\n", 'green'))
		
		print(colored(" .____                                   ,              _______                .   .        .   ", 'red', attrs=['bold']))
		time.sleep(0.2)
		print(colored(" /      , __   `   ___. , _ , _     ___  /   ____      '   /      __.    __.   |   /   / ` _/_  ", 'red', attrs=['bold']))
		print(colored(" |__.   |'  `. | .'   ` |' `|' `.  /   `    (              |    .'   \ .'   \  |   |_-'  |  |   ", 'red', attrs=['bold']))
		time.sleep(0.2)
		print(colored(" |      |    | | |    | |   |   | |    |    `--.           |    |    | |    |  |   |  \  |  |   ", 'red', attrs=['bold']))
		print(colored(" /----/ /    | /  `---| /   '   / `.__/|   \___.'          /     `._.'  `._.' /\__ /   \ /  \__/", 'red', attrs=['bold']))
		time.sleep(0.2)
		print(colored("                  \___/                                                                         \n\n", 'red', attrs=['bold']))
			
	def arp_logo(self):
		os.system('clear')
		print(colored("         _                   _           _          _            _          _            _            _      ", 'magenta'))
		print(colored("        / /\                /\ \        /\ \       / /\         /\ \       /\ \         /\ \         /\ \    ", 'magenta'))
		print(colored("       / /  \              /  \ \      /  \ \     / /  \       /  \ \     /  \ \       /  \ \       /  \ \   ", 'magenta'))
		print(colored("      / / /\ \            / /\ \ \    / /\ \ \   / / /\ \__   / /\ \ \   / /\ \ \     / /\ \ \     / /\ \ \  ", 'magenta'))
		time.sleep(0.2)
		print(colored("     / / /\ \ \          / / /\ \_\  / / /\ \_\ / / /\ \___\ / / /\ \_\ / / /\ \ \   / / /\ \ \   / / /\ \_\ ", 'magenta'))
		print(colored("    / / /  \ \ \        / / /_/ / / / / /_/ / / \ \ \ \/___// / /_/ / // / /  \ \_\ / / /  \ \_\ / /_/_ \/_/ ", 'magenta'))
		print(colored("   / / /___/ /\ \      / / /__\/ / / / /__\/ /   \ \ \     / / /__\/ // / /   / / // / /   / / // /____/\    ", 'magenta'))
		print(colored("  / / /_____/ /\ \    / / /_____/ / / /_____/_    \ \ \   / / /_____// / /   / / // / /   / / // /\____\/    ", 'magenta'))
		time.sleep(0.2)
		print(colored(" / /_________/\ \ \  / / /\ \ \  / / /      /_/\__/ / /  / / /      / / /___/ / // / /___/ / // / /          ", 'magenta'))
		print(colored("/ / /_       __\ \_\/ / /  \ \ \/ / /       \ \/___/ /  / / /      / / /____\/ // / /____\/ // / /           ", 'magenta'))
		time.sleep(0.2)
		print(colored("\_\___\     /____/_/\/_/    \_\/\/_/         \_____\/   \/_/       \/_________/ \/_________/ \/_/            ", 'magenta'))
		print(colored("\t\t\t\t\t     Made By AstroMh", 'magenta'))
		
	def inject_logo(self):
		os.system("clear")
		print(colored("\t\t                                       |", 'green', attrs=['bold']))
		time.sleep(0.1)
		print(colored("\t\t                 ,------------=--------|___________|", 'green', attrs=['bold']))
		print(colored("\t\t-=============%%%|   code  |  |______|_|___________|", 'green', attrs=['bold']))
		time.sleep(0.1)
		print(colored("\t\t|                | | | | | | ||| | | | |___________|", 'green', attrs=['bold']))
		print(colored("\t\tMade By AstroMh", 'green', attrs=['bold', 'reverse', 'blink']) + colored("  `------------=--------|           |", 'green', attrs=['bold']))
		time.sleep(0.1)
		print(colored("\t\t______________                         |\n\n", 'green', attrs=['bold']))
		
	
	def listener_logo(self):
		os.system("clear")
		print("                       ______")
		print("                    .-"      "-.")
		time.sleep(0.4)
		print("                   /            \ ")
		print("       _          |              |          _")
		print("      ( \         |,  .-.  .-.  ,|         / )")
		time.sleep(0.4)
		print('       > "=._     | )(__/  \__)( |     _.=" <')
		print('      (_/"=._"=._ |/     /\     \| _.="_.="\_)')
		print('             "=._ (_     ^^     _)"_.="')
		print('                 "=\__|IIIIII|__/="')
		time.sleep(0.4)
		print('                _.="| \IIIIII/ |"=._')
		print('      _     _.="_.="\          /"=._"=._     _')
		print('     ( \_.="_.="     `--------`     "=._"=._/ )')
		print('      > _.="                            "=._ <')
		print('     (_/          ' + colored(' Made By AstroMh ', 'red', attrs=['blink']) + '         \_)\n\n')
		time.sleep(0.4)
		print(colored("[!]", 'yellow') + colored(" TYPE ", 'cyan') + "help" + colored(" FOR THE COMMAND MENU!\n", 'cyan'))
		print(colored("[!]", "yellow") + " CTRL + C to exit to main programm.\n")

	def sniffer_logo(self):
		os.system('clear')
		print(colored("\n    //   ) )                        //  ) )     //  ) )                      ", 'blue', attrs=['bold']))
		time.sleep(0.1)
		print(colored("   ((             __       ( )   __//__      __//__         ___        __    ", 'blue', attrs=['bold']))
		time.sleep(0.1)
		print(colored(r"     \\        //   ) )   / /     //          //          //___) )   //  ) ) ", 'blue', attrs=['bold']))
		time.sleep(0.1)
		print(colored("       ) )    //   / /   / /     //          //          //         //       ", 'blue', attrs=['bold']))
		time.sleep(0.1)
		print(colored("((___ / /    //   / /   / /     //          //          ((____     //        ", 'blue', attrs=['bold']))
		print(colored("\n\t\t\t\tMade By AstroMh", 'cyan', attrs=['blink']))
		time.sleep(0.1)
		
	def net_scanner_logo(self):
		os.system("clear")
		print(colored("  _   _      _      _____                                 ", 'yellow'))
		print(colored(" | \ | |    | |    / ____|                                ", 'yellow'))
		print(colored(" |  \| | ___| |_  | (___   ___ __ _ _ __  _ __   ___ _ __ ", 'yellow'))
		print(colored(" | . ` |/ _ \ __|  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|", 'yellow'))
		print(colored(" | |\  |  __/ |_   ____) | (_| (_| | | | | | | |  __/ |   ", 'yellow'))
		print(colored(" |_| \_|\___|\__| |_____/ \___\__,_|_| |_|_| |_|\___|_|   Made By AstroMh\n", 'yellow'))
		print(colored("===================================================\n\tIP\t\t\t    MAC Address\n===================================================", 'yellow'))
	
	
	
	
