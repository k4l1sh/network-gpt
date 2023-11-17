import logging
import socket
import requests

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s', filename='../logs.log')

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