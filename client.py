from socket import *

s = socket(AF_INET, SOCK_STREAM)
s.connect(("192.168.10.3", 8080))

params = "username=devil&password=123456"
s.send("REGISTER\r\n".encode())
s.send(f"Content-Length: {len(params)}\r\n".encode())
s.send("\r\n".encode())
s.send(params.encode())

s.close()