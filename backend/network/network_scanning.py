import logging
import nmap
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network
from .ip_utils import is_valid_ip_network, get_host_by_name

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s', filename='../logs.log')

def scan_single_host(host, arguments=''):
    nm = nmap.PortScanner()
    try:
        logging.debug(f"Scanning host {host} with arguments {arguments}")
        nm.scan(hosts=host, arguments=arguments)
        host_info = {
            "state": nm[host].state(),
            "protocols": nm[host].all_protocols(),
            "ports": {}
        }
        for protocol in nm[host].all_protocols():
            lport = nm[host][protocol].keys()
            for port in lport:
                port_info = {k: v for k, v in nm[host][protocol][port].items() if v}
                if port_info:
                    host_info["ports"][port] = port_info
        if not host_info["ports"]:
            del host_info["ports"]
        if not any(host_info["ports"].get(p) for p in host_info["protocols"]):
            del host_info["protocols"]
        logging.info(f"Host {host}: {host_info}")
        return host, host_info
    except Exception:
        return host, {}

def network_scan(hosts=None, arguments=''):
    logging.info(f"Starting network scan for hosts {hosts} with arguments {arguments}")
    scan = {'host':hosts,'arguments':arguments,'results':{}}
    if is_valid_ip_network(hosts):
        hosts_list = [str(ip) for ip in ip_network(hosts).hosts()]
    else:
        ipv4_regex = r'(\b25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(\b25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(\b25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(\b25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        hosts_list = [".".join(match) for match in re.findall(ipv4_regex, hosts)]
    if not hosts_list:
        hosts_list = [get_host_by_name(hosts)]
    with ThreadPoolExecutor(max_workers=256) as executor:
        future_to_host = {executor.submit(scan_single_host, host, arguments): host for host in hosts_list}
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                _, host_info = future.result()
                if host_info:
                    scan['results'][host] = host_info
            except Exception:
                pass
    logging.info(f"Network scan completed successfully for the hosts {hosts} and arguments {arguments}")
    return scan