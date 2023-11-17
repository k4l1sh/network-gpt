import os
import json
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import openai
import nmap
from dotenv import load_dotenv
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network, IPv4Network
import traceback
import sys
import netifaces
from scapy.all import sniff, IP, TCP, UDP
from pydantic import BaseModel
from fastapi.responses import StreamingResponse
from time import sleep
import socket
import re
from collections import defaultdict
import subprocess
import requests

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s', filename='logs.log')
# Set OpenAI API key
openai.api_key = os.getenv('OPENAI_API_KEY')

# Initialize FastAPI app
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Function to perform network scan on a single host
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
        #logging.error(f"Error during scan of {host}: {''.join(traceback.format_exception(*sys.exc_info()))}")
        return host, {}

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
    
# Function to perform network scan
def network_scan(hosts, arguments=''):
    logging.info(f"Starting network scan for hosts {hosts} with arguments {arguments}")
    scan_results = {}
    if is_valid_ip_network(hosts):
        hosts_list = [str(ip) for ip in ip_network(hosts).hosts()]
    else:
        ipv4_regex = r'(\b25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(\b25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(\b25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(\b25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        hosts_list = [".".join(match) for match in re.findall(ipv4_regex, hosts)]
    if not hosts_list:
        hosts_list = [get_host_by_name(hosts)]
    with ThreadPoolExecutor(max_workers=64) as executor:
        future_to_host = {executor.submit(scan_single_host, host, arguments): host for host in hosts_list}
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                _, host_info = future.result()
                if host_info:
                    scan_results[host] = host_info
            except Exception:
                logging.error(traceback.format_exception(*sys.exc_info()))
    logging.info(f"Network scan completed successfully for the hosts {hosts} and arguments {arguments}")
    return scan_results

# Function to get the server's own subnet
def get_own_subnet():
    # Identify the default gateway and its interface
    gws = netifaces.gateways()
    default_gateway = gws['default'][netifaces.AF_INET]
    gateway, interface = default_gateway

    # Get the IP address and netmask of the interface
    addrs = netifaces.ifaddresses(interface)
    ip_info = addrs[netifaces.AF_INET][0]
    ip_address = ip_info['addr']
    netmask = ip_info['netmask']

    # Calculate the network
    network = IPv4Network(f"{ip_address}/{netmask}", strict=False)
    return str(network)

def capture_packet_info(packet):
    packet_info = {}
    if IP in packet:
        packet_info['src_ip'] = packet[IP].src
        packet_info['dst_ip'] = packet[IP].dst
    if TCP in packet:
        packet_info['protocol'] = 'TCP'
        packet_info['src_port'] = packet[TCP].sport
        packet_info['dst_port'] = packet[TCP].dport

    elif UDP in packet:
        packet_info['protocol'] = 'UDP'
        packet_info['src_port'] = packet[UDP].sport
        packet_info['dst_port'] = packet[UDP].dport
    return packet_info

def capture_packets(duration=15):
    logging.info(f"Capturing packets for {duration} seconds")
    packets = sniff(timeout=duration)
    packet_counts = defaultdict(int)
    for packet in packets:
        packet_info = capture_packet_info(packet)
        packet_key = tuple(packet_info.items())
        packet_counts[packet_key] += 1
    aggregated_packets = [{"count": count, **dict(packet_key)} for packet_key, count in packet_counts.items()]
    return aggregated_packets

def ping_host(host, count=4):
    logging.info(f"Sending {count} requests to {host}")
    try:
        output = subprocess.check_output(['ping', '-c', str(count), host], stderr=subprocess.STDOUT, universal_newlines=True)
        results = output
    except subprocess.CalledProcessError as e:
        results = str(e.output)
    return results.replace("\n", "<br/>")
    
def get_ip_address(private=True):
    if private:
        logging.info("Capturing private ip")
        # Get private IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP
    else:
        logging.info("Capturing public ip")
        try:
            response = requests.get('https://api.ipify.org?format=json')
            return response.json().get('ip', 'Unable to get public IP')
        except requests.RequestException:
            return 'Error: Unable to get public IP'

# Network scan function signature for ChatGPT
signature_network_scan = {
    "name": "network_scan",
    "description": "Perform a network scan using nmap",
    "parameters": {
        "type": "object",
        "properties": {
            "hosts": {
                "type": "string",
                "description": "The host(s) to scan, can be a single IP, a range, or a subnet"
            },
            "arguments": {
                "type": "string",
                "description": "The arguments to pass to nmap, such as scan type and options"
            },
            "own_network": {
                "type": "boolean",
                "description": "Detect if the user intends to scan their network"
            }
        },
        "required": ["hosts"]
    }
}

signature_capture_packets = {
    "name": "capture_packets",
    "description": "Capture network packets for and aggregate them",
    "parameters": {
        "type": "object",
        "properties": {
            "duration": {
                "type": "integer",
                "description": "Duration in seconds for which to capture packets",
                "default": 5
            }
        },
        "required": []
    }
}

signature_ping = {
    "name": "ping_host",
    "description": "Ping a specified host to check its reachability",
    "parameters": {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The host to ping"
            },
            "count": {
                "type": "integer",
                "description": "Number of echo requests to send",
                "default": 4
            }
        },
        "required": ["host"]
    }
}

signature_get_ip = {
    "name": "get_ip_address",
    "description": "Get my IP address",
    "parameters": {
        "type": "object",
        "properties": {
            "private": {
                "type": "boolean",
                "description": "Flag to indicate if the private IP should be retrieved instead of the public IP",
                "default": True
            }
        },
        "required": []
    }
}


def log_streamer():
    with open('logs.log', 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                sleep(0.1)
                continue
            yield f"data: {line}\n\n"

@app.get("/streamlogs/")
async def stream_logs():
    return StreamingResponse(log_streamer(), media_type="text/event-stream")

# Helper functions for token estimation and limiting context
def estimate_token_count(message):
    words = message.split()
    return len(words) * 4

def limit_context_to_max_tokens(messages, max_tokens=10000):
    limited_messages = []
    total_tokens = 0
    for message in reversed(messages):
        msg_token_count = estimate_token_count(message["content"])
        if total_tokens + msg_token_count <= max_tokens:
            total_tokens += msg_token_count
            limited_messages.append(message)
        else:
            break
    return list(reversed(limited_messages))

# Function to call ChatGPT API
def chat_with_openai(messages, model, function_call="auto"):
    try:
        logging.info('Calling GPT API...')
        res = openai.ChatCompletion.create(
            model=model,
            messages=messages,
            functions=[signature_network_scan, signature_capture_packets, signature_ping, signature_get_ip],
            function_call=function_call
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class Message(BaseModel):
    message: list
    model: str

# Endpoint to receive and process message
@app.post("/networkgpt/")
async def networkgpt(message_data: Message):
    message = message_data.message
    model = message_data.model
    messages = limit_context_to_max_tokens(message)
    llm_system_prompt = """You are Network GPT, a virtual assistant with the capability to process text requests and perform specific network functions. 
If a user requests a network scan, invoke the 'network_scan' function to initiate the scan.
Otherwise, respond with appropriate information or guidance based on the user's request.
"""
    messages.insert(0, {"role": "system", "content": llm_system_prompt})
    res = chat_with_openai(messages, model)

    # Check for network scan function call
    response = res["choices"][0]["message"]
    if response.get("function_call"):
        function_name = response["function_call"]["name"]
        function_results = {}
        args = json.loads(response["function_call"]["arguments"])
        if function_name == "network_scan":
            if args.get("own_network"):
                hosts = get_own_subnet()
            else:
                hosts = args.get("hosts")
            scan_results = network_scan(
                hosts=hosts,
                arguments=args.get("arguments", "")
            )
            function_results['scan_results'] = scan_results
        if function_name == "capture_packets":
            packet_results = capture_packets(duration=args.get("duration", 5))
            function_results['packet_results'] = packet_results
        if function_name == "ping_host":
            ping_results = ping_host(host=args.get("host"), count=args.get("count", 4))
            function_results['ping_results'] = ping_results
        if function_name == "get_ip_address":
            ip_results = get_ip_address(private=args.get("private", True))
            function_results['my_ip'] = ip_results
        return {"response": json.dumps(function_results)}
    else:
        return {"response": res["choices"][0]["message"]["content"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
