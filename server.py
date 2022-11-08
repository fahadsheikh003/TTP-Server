from socket import *
from constants import *
from concurrent.futures import ThreadPoolExecutor
from pymongo import MongoClient
from rsa import generate_key, revocate_key
from secrets import randbits
from random_prime_number_generator import get_prime
from utils import generator_check
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode

class TTP:
    def __init__(self) -> None:
        self.__sock = socket(AF_INET, SOCK_STREAM)
        # self.__sock.settimeout(TIME_OUT)
        
        try:
            self.__sock.bind(('', TTP_PORT))
        except:
            print(Exception(f"Unable to bind {TTP_PORT} to socket"))
            exit(1)

        self.__sock.listen(MAX_CONNECTIONS_ALLOWED)
        
        try:
            self.__database = MongoClient(CONNECTION_URI)['USERS']
        except:
            print(Exception("Unable to connect to database"))
            exit(1)

    def wait_for_connections(self):
        executor = ThreadPoolExecutor(max_workers=MAX_THREADS_ALLOWED)
        while True:
            client_socket, client_address = self.__sock.accept()
            executor.submit(self.handle_request, client_socket, client_address)

    def handle_login(self, client_socket: socket, cipher: Fernet, credentials: tuple):
        collection = self.__database['Users']
        user = collection.find_one({'_id':credentials[0]})
        
        if user == None:
            client_socket.send(f"{RESPONSE} 404 {BAD_REQUEST}\r\n\r\n".encode())
        elif user['_id'] == credentials[0] and user['pass'] == credentials[1]:
            content = f"d={user['d']}&n={user['n']}"
            encrypted_content = cipher.encrypt(content.encode())

            client_socket.send(f"{RESPONSE} 200 {OK}\r\n".encode())
            client_socket.send(f"Content-Length: {len(encrypted_content)}\r\n".encode())
            client_socket.send("\r\n".encode())
            client_socket.send(encrypted_content)

        else:
            client_socket.send(f"{RESPONSE} 402 {BAD_REQUEST}\r\n\r\n".encode())

    def handle_register(self, client_socket: socket, cipher: Fernet, credentials: tuple):
        collection = self.__database['Users']
        users = collection.find({'_id':credentials[0]})
        
        users = list(users)
        
        if len(users) != 0:
            client_socket.send(f"{RESPONSE} 402 {BAD_REQUEST}\r\n\r\n".encode())
        else:
            p, q, n, phi, e, d = generate_key()

            collection.insert_one({
                '_id': credentials[0], 
                'pass': credentials[1],
                'ip': '',
                'port': 0,
                'p': hex(p),
                'q': hex(q),
                'n': hex(n),
                'phi': hex(phi),
                'e': hex(e),
                'd': hex(d)
            })

            content = f"d={hex(d)}&n={hex(n)}"
            encrypted_content = cipher.encrypt(content.encode())

            client_socket.send(f"{RESPONSE} 200 {OK}\r\n".encode())
            client_socket.send(f"Content-Length: {len(encrypted_content)}\r\n".encode())
            client_socket.send("\r\n".encode())
            client_socket.send(encrypted_content)

    def handle_get_ip_and_port(self, client_socket: socket, cipher: Fernet, credentials: tuple, username: str):
        collection = self.__database['Users']
        user = collection.find_one({'_id':credentials[0]})
        
        if user == None:
            client_socket.send(f"{RESPONSE} 404 {BAD_REQUEST}\r\n\r\n".encode())
        elif user['_id'] == credentials[0] and user['pass'] == credentials[1]:
            user = collection.find_one({'_id':username})

            if user == None:
                client_socket.send(f"{RESPONSE} 401 {BAD_REQUEST}\r\n\r\n".encode())
            else:
                if user['ip'] == '' or user['port'] == 0:
                    client_socket.send(f"{RESPONSE} 403 {BAD_REQUEST}\r\n\r\n".encode())
                else:
                    content = f"ip={user['ip']}&port={user['port']}"
                    encrypted_content = cipher.encrypt(content.encode())

                    client_socket.send(f"{RESPONSE} 200 {OK}\r\n".encode())
                    client_socket.send(f"Content-Length: {len(encrypted_content)}\r\n".encode())
                    client_socket.send("\r\n".encode())
                    client_socket.send(encrypted_content)

        else:
            client_socket.send(f"{RESPONSE} 402 {BAD_REQUEST}\r\n\r\n".encode())

    def handle_get_public_key(self, client_socket: socket, cipher: Fernet, credentials: tuple, username: str):
        collection = self.__database['Users']
        user = collection.find_one({'_id':credentials[0]})
        
        if user == None:
            client_socket.send(f"{RESPONSE} 404 {BAD_REQUEST}\r\n\r\n".encode())
        elif user['_id'] == credentials[0] and user['pass'] == credentials[1]:
            user = collection.find_one({'_id':username})

            if user == None:
                client_socket.send(f"{RESPONSE} 401 {BAD_REQUEST}\r\n\r\n".encode())
            else:
                content = f"e={user['e']}&n={user['n']}"
                encrypted_content = cipher.encrypt(content.encode())

                client_socket.send(f"{RESPONSE} 200 {OK}\r\n".encode())
                client_socket.send(f"Content-Length: {len(encrypted_content)}\r\n".encode())
                client_socket.send("\r\n".encode())
                client_socket.send(encrypted_content)

        else:
            client_socket.send(f"{RESPONSE} 402 {BAD_REQUEST}\r\n\r\n".encode())

    def handle_generate_key(self, client_socket: socket, cipher: Fernet, credentials: tuple):
        collection = self.__database['Users']
        user = collection.find_one({'_id':credentials[0]})
        
        if user == None:
            client_socket.send(f"{RESPONSE} 404 {BAD_REQUEST}\r\n\r\n".encode())
        elif user['_id'] == credentials[0] and user['pass'] == credentials[1]:
            p, q, n, phi, e, d = generate_key()

            collection.update_many({'_id': credentials[0]}, {'$set': {
                'p': hex(p),
                'q': hex(q),
                'n': hex(n),
                'phi': hex(phi),
                'e': hex(e),
                'd': hex(d)
            }})

            content = f"d={hex(d)}&n={hex(n)}"
            encrypted_content = cipher.encrypt(content.encode())

            client_socket.send(f"{RESPONSE} 200 {OK}\r\n".encode())
            client_socket.send(f"Content-Length: {len(encrypted_content)}\r\n".encode())
            client_socket.send("\r\n".encode())
            client_socket.send(encrypted_content)

        else:
            client_socket.send(f"{RESPONSE} 402 {BAD_REQUEST}\r\n\r\n".encode())

    def handle_revocate_key(self, client_socket: socket, cipher: Fernet, credentials: tuple):
        collection = self.__database['Users']
        user = collection.find_one({'_id':credentials[0]})
        
        if user == None:
            client_socket.send(f"{RESPONSE} 404 {BAD_REQUEST}\r\n\r\n".encode())
        elif user['_id'] == credentials[0] and user['pass'] == credentials[1]:
            p = int(user['p'], 0)
            q = int(user['q'], 0)
            n, phi, e, d = revocate_key(p, q)

            collection.update_one({'_id': credentials[0]}, {'$set': {
                'e': hex(e),
                'd': hex(d)
            }})

            content = f"d={hex(d)}&n={hex(n)}"
            encrypted_content = cipher.encrypt(content.encode())

            client_socket.send(f"{RESPONSE} 200 {OK}\r\n".encode())
            client_socket.send(f"Content-Length: {len(encrypted_content)}\r\n".encode())
            client_socket.send("\r\n".encode())
            client_socket.send(encrypted_content)

        else:
            client_socket.send(f"{RESPONSE} 402 {BAD_REQUEST}\r\n\r\n".encode())

    def handle_set_ip_and_port(self, client_socket: socket, credentials: tuple, address: tuple, port: str):
        collection = self.__database['Users']
        user = collection.find_one({'_id':credentials[0]})
        
        if user == None:
            client_socket.send(f"{RESPONSE} 404 {BAD_REQUEST}\r\n\r\n".encode())
        elif user['_id'] == credentials[0] and user['pass'] == credentials[1]:
            try:
                port = int(port)
            except:
                client_socket.send(f"{RESPONSE} 403 {BAD_REQUEST}\r\n\r\n".encode())

            collection.update_one({'_id': credentials[0]}, {'$set': {
                'ip': address[0],
                'port': port
            }})

            client_socket.send(f"{RESPONSE} 200 {OK}\r\n".encode())
            client_socket.send("\r\n".encode())

        else:
            client_socket.send(f"{RESPONSE} 402 {BAD_REQUEST}\r\n\r\n".encode())

    def receive_message(self, client_socket: socket, cipher: Fernet = None) -> tuple:
        messege = client_socket.recv(BUFFER_SIZE)
        while "\r\n\r\n".encode() not in messege and len(messege) > 0:
            messege += client_socket.recv(BUFFER_SIZE)

        text_messege, crlf, data_message = messege.partition("\r\n\r\n".encode())

        # Divide text part into lines
        lines = text_messege.decode().split("\r\n")

        content_length = None

        # Find if the value of content length is provided
        for line in lines:
            if "Content-Length: " in line:
                content_length = int(line[16:])

        if content_length != None:
            # Keep reading data message until the number of bytes indicated by content length is received
            while content_length-len(data_message) > 0:
                data_message += client_socket.recv(BUFFER_SIZE)

        if cipher != None:
            data_message = cipher.decrypt(data_message)
        data_message = data_message.decode()
        return lines, data_message

    def handshake(self, client_socket: socket) -> bytes:
        p = get_prime(DH_BITS)
        g = randbits(GEN_BITS)
        while not generator_check(p, g):
            g = randbits(GEN_BITS)

        a = randbits(GEN_BITS)
        A = pow(g, a, p)

        content = f"p={p}&g={g}&A={A}"

        client_socket.send(f"{HANDSHAKE}\r\n".encode())
        client_socket.send(f"Content-Length: {len(content)}\r\n".encode())
        client_socket.send("\r\n".encode())
        client_socket.send(content.encode())

        lines, message = self.receive_message(client_socket)
        if "200 OK" in lines[0]:
            B = int(message[2:])
            K = pow(B, a, p)

            K = K.to_bytes((K.bit_length() + 7) // 8, 'little')
            if len(K) < FERNET_KEYSIZE:
                K += b'\xcc' * (FERNET_KEYSIZE - len(K))
            else:
                K = K[:FERNET_KEYSIZE]

            return urlsafe_b64encode(K)

        return b""

    def handle_request(self, client_socket: socket, client_address: tuple):
        key = self.handshake(client_socket)
        cipher = Fernet(key)

        lines, data_message = self.receive_message(client_socket, cipher)
        
        print(f"Request Received from {client_address[0]}:{client_address[1]}")
        print("\n".join(lines))
        print(data_message, end='\n\n')

        with open(LOG_FILE, 'a') as f:
            f.write(f"{client_address[0]}\t{lines[0]}\t{data_message}\n")

        match lines[0].split()[0]:
            case "LOGIN":
                params = data_message.split('&')
                self.handle_login(client_socket, cipher, (params[0][9:], params[1][9:]))
            
            case "REGISTER":
                params = data_message.split('&')
                self.handle_register(client_socket, cipher, (params[0][9:], params[1][9:]))

            case "GENERATE":
                params = data_message.split('&')
                self.handle_generate_key(client_socket, cipher, (params[0][9:], params[1][9:]))

            case "REVOCATE":
                params = data_message.split('&')
                self.handle_revocate_key(client_socket, cipher, (params[0][9:], params[1][9:]))

            case "SET":
                params = data_message.split('&')
                self.handle_set_ip_and_port(client_socket, (params[0][9:], params[1][9:]), client_address, params[2][5:])

            case "GET":
                match lines[0].split()[1]:
                    case "KEY":
                        params = data_message.split('&')
                        self.handle_get_public_key(client_socket, cipher, (params[0][9:], params[1][9:]), params[2][10:])

                    case "ADDRESS":
                        params = data_message.split('&')
                        self.handle_get_ip_and_port(client_socket, cipher, (params[0][9:], params[1][9:]), params[2][10:])

        client_socket.shutdown(SHUT_RDWR)
        client_socket.close()

ttp = TTP()
ttp.wait_for_connections()