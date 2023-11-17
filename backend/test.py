import requests
import socket

def get_ip_address(public=False):
    if public:
        try:
            response = requests.get('https://api.ipify.org?format=json')
            return response.json().get('ip', 'Unable to get public IP')
        except requests.RequestException:
            return 'Error: Unable to get public IP'
    else:
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
    
print(get_ip_address())