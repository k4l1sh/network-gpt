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
            functions=[signature_network_scan],
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
        if function_name == "network_scan":
            args = json.loads(response["function_call"]["arguments"])
            if args.get("own_network"):
                hosts = get_own_subnet()
            else:
                hosts = args.get("hosts")
            scan_results = network_scan(
                hosts=hosts,
                arguments=args.get("arguments", "")
            )
            messages.append({"role": "function", "name": "network_scan", "content": scan_results})
        return {"response": scan_results}
    else:
        return {"response": res["choices"][0]["message"]["content"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
