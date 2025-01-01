

# Enigmas's Toolkit

*This is a genral toolkit for penetration testing*

## Usage
This Programe is consited of different parts and options:
	**1. Backdoor and Listener (for more informaation visit: )**
	**2. Code Injector**
	**3. Packet Sniffer**
	**4. ARP Spoofer**
	**5. Network Scanner**

---
- BackDoor Listener
This options allow the attacker to get full system control on the target's machine. it comes with
a Listener as well which contains many other options. To learn more about the backdoor please
visit: [BackDoor]()

- Code Injector
This programe allows the attacker to inject javascript code to the target's browser. Using the
BeefXSS programe this option allows you to fully take control of the target's browser.
Note: Before using this options the ARP Spoofer programe must be runned. 

- Packet Sniffer
This options allow you to see the packets flying through your computer (after ARP Spoofer).
It also marks out login attempts so in case of a *http login* you can see the username and password.

- ARP Spoofer
This is the base programe for many of the previous options. Spoofing the target's ip address and Access 
Point's Ip address this programe puts you straight in the middle of the network connection making it useful
during a MITM (Man In The Middle) attack

- Network Scanner
This small programe shows every single devices in the network with their IPs and MACs. it can also
write the output to a file.

---
## Instalation

To install this project, follow these steps:

	```bash
	git clone 
	cd  
	python install -r requirements.txt

---
