# NetHawk - Network Security Toolkit

NetHawk is a comprehensive network security toolkit for ethical hacking and penetration testing. This toolkit includes a variety of tools for network scanning, packet sniffing, ARP spoofing, and more.

## Features

- **Backdoor Listener**: A reverse shell listener for connecting to remote systems
- **Code Injector**: Inject JavaScript code into HTTP responses
- **Packet Sniffer**: Capture and analyze network traffic
- **ARP Spoofer**: Perform ARP spoofing attacks for network traffic interception
- **Network Scanner**: Scan local networks to discover active hosts
- **Web Scanner**: Perform security scans on websites to identify vulnerabilities like XSS, SQL Injection, and more

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/NetHawk.git
cd NetHawk
```

2. Create a virtual environment and activate it:
```
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install the required dependencies:
```
pip install -r requirements.txt
```

4. For some features, you may need additional tools:
   - For Code Injector: `apt-get install beef-xss` (on Debian/Ubuntu)
   - For ARP Spoofing: Make sure IP forwarding is enabled (`sudo sysctl -w net.ipv4.ip_forward=1`)
   - For Web Scanner: Make sure you have Python libraries like `requests`, `beautifulsoup4`, and `dnspython` installed

## Usage

Run the main application (with the virtual environment activated):
```
sudo python main.py
```

Note: Most of the tools require root/administrator privileges to function correctly.

### Tool Selection

Once the application is running, you'll be presented with a menu to select the desired tool:
1. Backdoor Listener
2. Code Injector
3. Packet Sniffer
4. ARP Spoofer
5. Network Scanner
6. Web Scanner
7. Exit

### Web Scanner Usage

The Web Scanner allows you to detect common web vulnerabilities in target websites:

- Cross-Site Scripting (XSS)
- SQL Injection
- Command Injection
- Local File Inclusion (LFI)
- Open Redirects
- CSRF vulnerabilities
- And more...

Reports can be generated in HTML, JSON, or CSV formats for easy analysis.

### Notes for macOS Users

When running on macOS, you may need to install additional dependencies for some features. The application will detect missing dependencies and inform you. Some features (like `netfilterqueue`) may have limited functionality on macOS.

## Ethical Considerations

This toolkit is developed for educational purposes and should only be used in controlled environments or on systems you own or have explicit permission to test. Unauthorized use of these tools against systems without permission is illegal and unethical.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

python3 -m venv venv && source venv/bin/activate
