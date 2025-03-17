# NetHawk: Network Toolkit

NetHawk is a Python-based network toolkit designed for various network operations such as packet sniffing, ARP spoofing, code injection, and more. The toolkit also includes a built-in backdoor with advanced capabilities like keylogging, file upload/download, and screenshot taking. Built using Python and leveraging libraries like `scapy`, `netfilterqueue`, and `termcolor`, NetHawk provides a user-friendly interface for network analysis and manipulation.

## Features

- **Packet Sniffing**: Capture and analyze network packets, including HTTP requests and login credentials.
- **ARP Spoofing**: Perform ARP spoofing attacks to intercept network traffic.
- **Code Injection**: Inject JavaScript code into HTTP responses.
- **Network Scanning**: Scan the network to discover active devices and their IP/MAC addresses.
- **Backdoor Listener**: Set up a listener for reverse shell connections with advanced capabilities:
  - **Keylogging**: Capture keystrokes on the target machine.
  - **File Upload/Download**: Upload and download files to/from the target machine.
  - **Screenshot Taking**: Capture screenshots from the target machine.
  - **Encryption/Decryption**: Encrypt and decrypt files on the target machine.
  - **Replication**: Copy the backdoor to other directories on the target machine.
  - **Session Management**: Restart or terminate the backdoor session.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/NetHawk.git
   cd NetHawk
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the toolkit**:
   ```bash
   python main.py
   ```

## Usage

### Main Menu
Upon running NetHawk, you will be presented with a main menu where you can select the desired operation:

1. **Backdoor Listener**: Set up a listener for reverse shell connections.
2. **Code Injector**: Inject JavaScript code into HTTP responses.
3. **Packet Sniffer**: Capture and analyze network packets.
4. **ARP Spoofer**: Perform ARP spoofing attacks.
5. **Network Scanner**: Scan the network for active devices.
6. **Exit**: Exit the toolkit.

### Backdoor Listener Options
When you select the **Backdoor Listener** option, you can use the following commands to interact with the target machine:

- **Keylogger**:
  - `keylogger start`: Start capturing keystrokes.
  - `keylogger dump`: Dump the captured keystrokes.
  - `keylogger stop`: Stop the keylogger.

- **File Upload/Download**:
  - `upload <file_path>`: Upload a file to the target machine.
  - `download <file_path>`: Download a file from the target machine.

- **Screenshot**:
  - `screenshot <file_path/name>`: Capture a screenshot from the target machine and save it locally.

- **Encryption/Decryption**:
  - `encrypt <directory>`: Encrypt all files in a specified directory on the target machine.
  - `decrypt <directory>`: Decrypt all files in a specified directory on the target machine.

- **Replication**:
  - `replicate <directory>`: Copy the backdoor to a specified directory on the target machine.

- **Session Management**:
  - `restart`: Restart the backdoor connection.
  - `exit`: Close the backdoor connection.
  - `terminate`: Terminate the backdoor session on both sides.

### Example Commands

- **Packet Sniffing**:
  ```bash
  python main.py
  ```
  Select option `3` and provide the network interface to sniff on.

- **ARP Spoofing**:
  ```bash
  python main.py
  ```
  Select option `4` and provide the target IP and access point IP.

- **Code Injection**:
  ```bash
  python main.py
  ```
  Select option `2` and provide your IP address to inject JavaScript code.

- **Backdoor Listener**:
  ```bash
  python main.py
  ```
  Select option `1` and use the commands mentioned above to interact with the target machine.

## Requirements

- Python 3.x
- scapy
- netfilterqueue
- termcolor
- keyboard
- pynput

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

NetHawk is intended for educational purposes only. The authors are not responsible for any misuse of this software. Use it at your own risk and only on networks you have permission to test.

---
