from ipaddress import ip_network, IPv4Network
import netifaces
import requests
import logging
import socket

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s', filename='logs.log')

def is_valid_ip_network(address):
    try:
        ip_network(address)
        return True
    except ValueError:
        return False

def get_host_by_name(address):
    try:
        return socket.gethostbyname(address)
    except socket.gaierror:
        return address

def get_own_subnet():
    gws = netifaces.gateways()
    default_gateway = gws['default'][netifaces.AF_INET]
    gateway, interface = default_gateway
    addrs = netifaces.ifaddresses(interface)
    ip_info = addrs[netifaces.AF_INET][0]
    ip_address = ip_info['addr']
    netmask_cidr = ip_network(f"0.0.0.0/{ip_info['netmask']}").prefixlen
    netmask = max(netmask_cidr, 24)
    network = IPv4Network(f"{ip_address}/{netmask}", strict=False)
    return str(network)

def get_ip_address():
    logging.info("Capturing private ip")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    logging.info("Capturing public ip")
    try:
        response = requests.get('https://api.ipify.org?format=json')
        return {'private':IP, 'public':response.json().get('ip', 'Unable to get public IP')}
    except requests.RequestException:
        return 'Error: Unable to get public IP'