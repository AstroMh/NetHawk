import requests
import random
import socket
import socks
from stem import Signal
from stem.control import Controller
from concurrent.futures import ThreadPoolExecutor
import re
from typing import List, Dict, Optional


class TorProxyChain:
    def __init__(self, proxy_file: str = None, tor_socks_port: int = 9050,
                 tor_control_port: int = 9051, tor_password: str = None):
        """
        Initialize Tor and Proxy Chain manager

        Args:
            proxy_file: Path to file containing proxy list
            tor_socks_port: Port for Tor SOCKS proxy
            tor_control_port: Port for Tor control connection
            tor_password: Password for Tor controller (if needed)
        """
        self.proxy_file = proxy_file
        self.tor_socks_port = tor_socks_port
        self.tor_control_port = tor_control_port
        self.tor_password = tor_password
        self.proxies = self._read_proxy_list()
        self.session = requests.Session()
        self.current_chain = []
        self._tor_process = None

    def _read_proxy_list(self) -> List[Dict]:
        """Read and parse proxy list from file"""
        proxies = []
        try:
            with open(self.proxy_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Support multiple formats:
                    # 1. host:port
                    # 2. host:port:user:pass
                    # 3. type://host:port
                    # 4. type://user:pass@host:port
                    if '://' in line:
                        # URL-style format
                        proxy_type, rest = line.split('://', 1)
                        if '@' in rest:
                            auth, hostport = rest.split('@', 1)
                            user, password = auth.split(':', 1)
                            host, port = hostport.split(':', 1)
                        else:
                            user, password = None, None
                            host, port = rest.split(':', 1)
                    else:
                        parts = line.split(':')
                        host = parts[0]
                        port = parts[1]
                        user = parts[2] if len(parts) > 2 else None
                        password = parts[3] if len(parts) > 3 else None
                        proxy_type = parts[4] if len(parts) > 4 else 'http'

                    proxies.append({
                        'type': proxy_type.lower(),
                        'host': host,
                        'port': int(port),
                        'username': user,
                        'password': password
                    })
        except Exception as e:
            print(f"Error reading proxy file: {e}")
        return proxies

    def start_tor(self) -> bool:
        """Start Tor process (if not already running)"""
        try:
            socks.set_default_proxy(socks.SOCKS5, "localhost", self.tor_socks_port)
            socket.socket = socks.socksocket
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            test_socket.connect(("example.com", 80))
            test_socket.close()
            return True
        except:
            try:
                from stem.process import launch_tor_with_config
                self._tor_process = launch_tor_with_config(
                    config={
                        'SocksPort': str(self.tor_socks_port),
                        'ControlPort': str(self.tor_control_port),
                    },
                    tor_cmd='tor'
                )
                return True
            except Exception as e:
                print(f"Failed to start Tor: {e}")
                return False

    def renew_tor_identity(self) -> bool:
        """Request new Tor circuit"""
        try:
            with Controller.from_port(port=self.tor_control_port) as controller:
                if self.tor_password:
                    controller.authenticate(password=self.tor_password)
                else:
                    controller.authenticate()
                controller.signal(Signal.NEWNYM)
                return True
        except Exception as e:
            print(f"Failed to renew Tor identity: {e}")
            return False

    def build_chain(self, chain_type: str = "tor_random", length: int = 3) -> List[Dict]:
        """
        Build a proxy chain

        Args:
            chain_type: One of:
                - "tor_only": Just use Tor
                - "tor_random": Tor + random proxies
                - "random": Just random proxies
                - "custom": Manually specified chain
            length: Number of proxies in chain (excluding Tor if used)
        """
        self.current_chain = []

        if chain_type == "tor_only":
            self.current_chain.append({
                'type': 'socks5',
                'host': 'localhost',
                'port': self.tor_socks_port
            })
        elif chain_type == "tor_random":
            self.current_chain.append({
                'type': 'socks5',
                'host': 'localhost',
                'port': self.tor_socks_port
            })
            available_proxies = [p for p in self.proxies if p not in self.current_chain]
            self.current_chain.extend(random.sample(available_proxies, min(length, len(available_proxies))))
        elif chain_type == "random":
            available_proxies = [p for p in self.proxies if p not in self.current_chain]
            self.current_chain.extend(random.sample(available_proxies, min(length, len(available_proxies))))

        return self.current_chain

    def _format_proxy_url(self, proxy: Dict) -> str:
        auth = ''
        if proxy.get('username'):
            auth = f"{proxy['username']}:{proxy.get('password', '')}@"

        if proxy['type'] in ['http', 'https']:
            return f"http://{auth}{proxy['host']}:{proxy['port']}"
        else:
            return f"{proxy['type']}://{auth}{proxy['host']}:{proxy['port']}"

    def activate_chain(self) -> bool:
        if not self.current_chain:
            return False

        # For single proxy, use requests' native proxy support
        if len(self.current_chain) == 1:
            proxy = self.current_chain[0]
            self.session.proxies = {
                'http': self._format_proxy_url(proxy),
                'https': self._format_proxy_url(proxy)
            }
            return True
        else:
            try:
                last_proxy = self.current_chain[-1]
                socks.set_default_proxy(
                    getattr(socks, f"PROXY_TYPE_{last_proxy['type'].upper()}"),
                    last_proxy['host'],
                    last_proxy['port'],
                    username=last_proxy.get('username'),
                    password=last_proxy.get('password')
                )
                socket.socket = socks.socksocket

                first_proxy = self.current_chain[0]
                self.session.proxies = {
                    'http': self._format_proxy_url(first_proxy),
                    'https': self._format_proxy_url(first_proxy)
                }
                return True
            except Exception as e:
                print(f"Failed to activate chain: {e}")
                return False

    def make_request(self, url: str, rotate_on_fail: bool = True, timeout: int = 30) -> Optional[requests.Response]:
        try:
            response = self.session.get(url, timeout=timeout)
            return response
        except Exception as e:
            if rotate_on_fail and len(self.proxies) > 1:
                print(f"Request failed, rotating proxies... ({e})")
                self.build_chain(chain_type="random")
                self.activate_chain()
                return self.make_request(url, rotate_on_fail=False, timeout=timeout)
            return None

    def test_proxy(self, proxy: Dict, test_url: str = "https://httpbin.org/ip", timeout: int = 10) -> bool:
        """Test if a proxy is working"""
        try:
            temp_session = requests.Session()
            proxy_url = self._format_proxy_url(proxy)
            temp_session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            response = temp_session.get(test_url, timeout=timeout)
            return response.status_code == 200
        except:
            return False

    def validate_proxies(self, test_url: str = "https://httpbin.org/ip", max_workers: int = 20) -> List[Dict]:
        """Validate all proxies in list and return working ones"""
        working_proxies = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.test_proxy, proxy, test_url): proxy for proxy in self.proxies}
            for future in futures:
                proxy = futures[future]
                try:
                    if future.result():
                        working_proxies.append(proxy)
                except:
                    pass

        self.proxies = working_proxies
        return working_proxies

    def close(self):
        """Clean up resources"""
        self.session.close()
        if self._tor_process:
            self._tor_process.terminate()
            self._tor_process.wait()


if __name__ == "__main__":
    tpc = TorProxyChain(proxy_file="proxies.txt")

    tpc.start_tor()

    tpc.build_chain(chain_type="tor_random", length=2)
    print("Current chain:", tpc.current_chain)

    tpc.activate_chain()

    response = tpc.make_request("https://httpbin.org/ip")
    if response:
        print("Response:", response.json())
    tpc.renew_tor_identity()
    working_proxies = tpc.validate_proxies()
    print(f"Working proxies: {len(working_proxies)}/{len(tpc.proxies)}")
    tpc.close()
