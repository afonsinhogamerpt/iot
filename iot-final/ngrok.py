import requests
import time
import os
from urllib.parse import urlparse

def get_ngrok_url(api_port, proto='http'):
    url = f'http://localhost:{api_port}/api/tunnels'
    for _ in range(10):
        try:
            res = requests.get(url)
            data = res.json()
            for tunnel in data['tunnels']:
                if tunnel['proto'] == proto:
                    return tunnel['public_url']
        except Exception:
            time.sleep(1)
    return None

if __name__ == '__main__':
    http_url = get_ngrok_url(4040, proto='https')
    tcp_url = get_ngrok_url(4041, proto='tcp')
    parse = urlparse(tcp_url)
    print(f'HTTP URL (frontend): {http_url}')
    print(f'TCP URL (broker): {tcp_url}')
    
    # Passa só o hostname para o dig
    os.system(f"dig {parse.hostname}")
