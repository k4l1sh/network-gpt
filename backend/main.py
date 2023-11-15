import os
import json
from fastapi import FastAPI, HTTPException
import openai
import nmap
from dotenv import load_dotenv
import logging

load_dotenv()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s:%(levelname)s: %(message)s', filename='logs.log')
# Set OpenAI API key
openai.api_key = os.getenv('OPENAI_API_KEY')
llm_model = "gpt-3.5-turbo"
llm_max_tokens = 15500

# Initialize FastAPI app
app = FastAPI()

# Function to perform network scan
def network_scan(hosts, arguments=''):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=hosts, arguments=arguments)
        logging.info(f"nmap command: {nm.command_line()}")
        logging.info("Network scan completed successfully")  # Log successful completion
        scan_results = {}
        for host in nm.all_hosts():
            host_info = {
                "state": nm[host].state(),
                "protocols": nm[host].all_protocols(),
                "ports": {}
            }
            for protocol in nm[host].all_protocols():
                lport = nm[host][protocol].keys()
                for port in lport:
                    host_info["ports"][port] = nm[host][protocol][port]
            scan_results[host] = host_info
        return scan_results
    except Exception as e:
        logging.error(f"Error during network scan: {e}")  # Log any exceptions
        raise


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
            }
        },
        "required": ["hosts"]
    }
}

# Function to call ChatGPT API
def chat_with_openai(messages, function_call="auto"):
    try:
        res = openai.ChatCompletion.create(
            model=llm_model,
            messages=messages,
            functions=[signature_network_scan],
            function_call=function_call
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint to receive and process message
@app.post("/process_message/")
async def process_message(message: str):
    llm_system_prompt = """You are a virtual assistant with the capability to process text requests and perform specific functions. 
If a user requests a network scan, invoke the 'network_scan' function to initiate the scan.
Otherwise, respond with appropriate information or guidance based on the user's request.
"""
    messages = [{"role": "system", "content": llm_system_prompt}, {"role": "user", "content": message}]
    res = chat_with_openai(messages)

    # Check for network scan function call
    response = res["choices"][0]["message"]
    if response.get("function_call"):
        function_name = response["function_call"]["name"]
        if function_name == "network_scan":
            args = json.loads(response["function_call"]["arguments"])
            scan_results = network_scan(
                hosts=args.get("hosts"),
                arguments=args.get("arguments")
            )
            messages.append({"role": "function", "name": "network_scan", "content": scan_results})
        return {"response": scan_results}
    else:
        return {"response": res["choices"][0]["message"]["content"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
