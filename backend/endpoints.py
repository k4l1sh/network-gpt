import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import openai
import logging
from pydantic import BaseModel
from fastapi.responses import StreamingResponse
from network.network_scanning import network_scan
from network.packet_capture import capture_packets
from network.ping_utils import ping_host
from network.ip_address import get_ip_address
from network.ip_utils import get_own_subnet
from dotenv import load_dotenv
from time import sleep
import json

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s', filename='logs.log')
openai.api_key = os.getenv('OPENAI_API_KEY')

def chat_with_openai(messages, model, function_call="auto"):
    signature_network_scan = {
        "name": "network_scan",
        "description": "Perform a network scan using nmap if the user wants a network scan",
        "parameters": {
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "string",
                    "description": "The host(s) to scan, can be a single IP, a range, or a subnet"
                },
                "arguments": {
                    "type": "string",
                    "description": "The arguments to pass to nmap, such as scan type and options available in nmap"
                },
                "own_network": {
                    "type": "boolean",
                    "description": "Detect if the user intends to scan their own network, otherwise set this to false"
                }
            },
            "required": []
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
        "description": "Get my own IP address",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
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

def log_streamer():
    with open('logs.log', 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                sleep(0.1)
                continue
            yield f"data: {line}\n\n"

class Message(BaseModel):
    message: list
    model: str

async def networkgpt(message_data: Message):
    message = message_data.message
    model = message_data.model
    messages = limit_context_to_max_tokens(message)
    llm_system_prompt = """You are Network GPT, a virtual assistant with the capability to process text requests and perform specific network functions. 
If the last user message explicitly requests a network scan, invoke the 'network_scan' function to initiate the scan.
If the last user message explicitly requests to capture their packets, invoke the 'capture_packets' function to initiate the capturing.
If the last user message explicitly requests to ping, invoke the 'ping_host' function to ping a host.
If the last user message explicitly requests their own IP address, invoke the 'get_ip_address' function to get their IP.
Otherwise, respond with appropriate information or guidance based on the user's request.
"""
    messages.insert(0, {"role": "system", "content": llm_system_prompt})
    res = chat_with_openai(messages, model)
    response = res["choices"][0]["message"]
    if response.get("function_call"):
        function_name = response["function_call"]["name"]
        function_results = {}
        args = json.loads(response["function_call"]["arguments"])
        if function_name == "network_scan":
            if args.get("own_network"):
                hosts = get_own_subnet()
            else:
                hosts = args.get("hosts", get_own_subnet())
            scan_results = network_scan(
                hosts=hosts,
                arguments=args.get("arguments", "")
            )
            function_results['scan'] = scan_results
        if function_name == "capture_packets":
            logging.info(f"Capturing packets for {args.get('duration', 5)} seconds")
            packet_results = capture_packets(duration=args.get("duration", 5))
            function_results['packet_results'] = packet_results
        if function_name == "ping_host":
            logging.info(f"Sending {args.get('count')} requests to {args.get('host')}")
            ping_results = ping_host(host=args.get("host"), count=args.get("count", 4))
            function_results['ping_results'] = ping_results
        if function_name == "get_ip_address":
            ip_results = get_ip_address()
            function_results['my_ip'] = ip_results
        return {"response": json.dumps(function_results)}
    else:
        return {"response": res["choices"][0]["message"]["content"]}

async def stream_logs():
    return StreamingResponse(log_streamer(), media_type="text/event-stream")