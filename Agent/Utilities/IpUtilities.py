import socket
import requests


def get_public_ip():
    public_ip = ""
    try:
        public_ip = requests.get('https://api.ipify.org').content.decode('utf8')
    except Exception as e:
        pass
    return public_ip


def get_local_ip():
    hostname = socket.gethostname()
    local_ip_address = socket.gethostbyname(hostname)
    return local_ip_address


def get_ip_tuple():
    return get_local_ip(), get_public_ip()

