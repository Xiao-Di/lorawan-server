import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_addr = "127.0.0.1"
port = 12255
data = b'hello'

s.sendto(data, (client_addr, port))
