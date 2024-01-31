#! /usr/bin/env python3

import socket
import select
import struct
import sys
import logging

from numbers_API import *

DEFAULT_HOST = ""
DEFAULT_PORT = 1337
DEFAULT_BYTES_RECV = 1024

class OnlineClient:
    def __init__(self, soc: socket.socket) -> None:
        self.soc = soc
        self.buffer = bytes()
        self.msg_length = -1
        self.is_auth = False
        

class Server:
    def __init__(self, user_credentials_file, listening_host=DEFAULT_HOST, listening_port=DEFAULT_PORT) -> None:
        self.listening_port = listening_port
        self.listening_host = listening_host
        self.user_credentials_file = user_credentials_file
        self.user_credentials = {}
        self.client_sockets = {}

    def read_user_cred_from_file(self):
        try:
            with open(self.user_credentials_file, "r") as file:
                for line in file:
                    username, password = line.strip().split(AUTH_SEP)
                    self.user_credentials[username] = password
        except FileNotFoundError as e:
            logging.error(f"Error: File '{self.user_credentials_file}' not found.")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error loading user credentials from file: {e}.")
            sys.exit(1)
        
        logging.debug(f"Successfully read user credentials.")

    def start(self):
        self.read_user_cred_from_file()

        # Create a TCP socket
        self._listen_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            # Bind the socket to a specific address and port
            self._listen_soc.bind((self.listening_host, self.listening_port))

            # Listen for incoming connections (max 5 connections in the backlog)
            self._listen_soc.listen(5)
            logging.info(f"Server listening on {self.listening_host}:{self.listening_port}")
        except socket.error as e:
            logging.error(f"Error listening on ({self.listening_host}:{self.listening_port}): {e}.")
            sys.exit(1)
            
        # Dict to keep track of online client sockets (Include the unique listen socket)
        self.client_sockets[self._listen_soc] = None

        # Start accept & serve clients
        self.server_loop()

    def accept_new_client(self):
        try:
            # New connection waiting in queue
            client_socket, client_address = self._listen_soc.accept()

            # Send a connected message to the client
            self.send_connected_msg(client_socket)
            
        except socket.error as e:
            logging.debug(f"Error accepting new connection: {e}.")
            client_socket.close()
            return

        # Add the new client socket to the dict
        self.client_sockets[client_socket] = OnlineClient(client_socket)
        logging.info(f"Accepted connection from {client_address}")

    def disconnect_client(self, soc: socket.socket):
        logging.info(f"Closing connection to {soc.getpeername()}.")
        soc.close()
        self.client_sockets.pop(soc)
        

    def server_loop(self):
        while True:
            # Use select to wait for any of the sockets to be ready for processing
            readable, _, _ = select.select(self.client_sockets.keys(), [], [])

            for soc in readable:
                if soc == self._listen_soc:
                    self.accept_new_client()
                else:
                    # Existing client socket, receive and process request
                    client = self.client_sockets[soc]
                    try:
                        bytes_to_read = client.msg_length - client.buffer if client.msg_length != -1 else DEFAULT_BYTES_RECV
                        data = soc.recv(bytes_to_read)
                    except socket.error as e:
                        logging.debug(f"Error receiving data from {soc.getpeername()}: {e}")

                     # Connection closed by the client or too many bytes received
                    if not data or (client.msg_length != -1 and len(data)+len(client.buffer) > client.msg_length):
                        self.disconnect_client(soc)
                        continue
                    
                    client.buffer += data
                    if client.msg_length == -1: # New message/Header yet received
                        client.msg_length = required_req_length(client.buffer)

                    if len(client.buffer) == client.msg_length:
                        response = self.handle_req(client)

                        if not response:
                            self.disconnect_client(soc)
                            continue

                        try:
                            soc.sendall(response)
                            client.msg_length = -1
                            client.buffer = b""
                        except socket.error as e:
                            logging.debug(f"Error sending data to {soc.getpeername()}: {e}")   
                            self.disconnect_client(soc)    
                        

    def send_connected_msg(self, soc: socket.socket):
        connected_msg = struct.pack(API_HEADER, APIResponse.CONNECTED.value, 0)
        soc.sendall(connected_msg)

    def handle_req(self, client: OnlineClient) -> bytes:
        try:
            req_id, args = unpack_req(client.buffer)
        except Exception as e:
            payload = APIError.INVALID_FORMAT.binary_value # Invalid request format
            return struct.pack(API_HEADER, APIResponse.ERROR.value, len(payload)) + payload

        if req_id is not APIRequest.AUTH and not client.is_auth:
            payload = APIError.UNAUTH_CLIENT.binary_value # Unauthenticated client error
            return struct.pack(API_HEADER, APIResponse.ERROR.value, len(payload)) + payload

        payload = b""
        res_id = None
        if req_id is APIRequest.AUTH and len(args) == 2:
            res_id, payload = self.handle_auth(client, *args)
        elif req_id is APIRequest.CALCULATE and len(args) == 3:
            res_id, payload = self.handle_calculate(*args)
        elif req_id is APIRequest.IS_PALINDROME and len(args) == 1:
            res_id, payload = self.handle_is_palindrome(*args)
        elif req_id is APIRequest.IS_PRIMARY and len(args) == 1:
            res_id, payload = self.handle_is_primary(*args)
        else:
            payload = APIError.UNSUPPORTED_REQUEST.binary_value # Unsupported request
            return struct.pack(API_HEADER, APIResponse.ERROR.value, len(payload)) + payload

        return struct.pack(API_HEADER, res_id.value, len(payload)) + payload

    def handle_auth(self, client: OnlineClient, username: str, password: str) -> tuple[APIResponse, bytes]:
        payload = b""
        if username in self.user_credentials and self.user_credentials[username] == password:
            payload = username.encode()
            client.is_auth = True
            logging.info(f"The client {client.soc.getpeername()} authenticated with '{username}'.")
        else:
            logging.debug(f"The client {client.soc.getpeername()} failed login with '{username}'.")
            client.is_auth = False

            
        return APIResponse.AUTH, payload

    def handle_calculate(self, op: MathOp, num1: int, num2: int) -> tuple[APIResponse, bytes]:
        result = 0
        try:
            if op is MathOp.ADD:
                result = num1 + num2
            elif op is MathOp.SUB:
                result = num1 - num2
            elif op is MathOp.MUL:
                result = num1 * num2
            elif op is MathOp.DIV:
                result = num1 / num2
            else: # Invalid request arguments
                return APIResponse.ERROR, APIError.INVALID_ARGUMENT.binary_value
        except ArithmeticError as e:
            return APIResponse.ERROR, APIError.INVALID_ARGUMENT.binary_value          

        return APIResponse.CALCULATE, struct.pack(CALCULATE_RESPONSE_FORMAT, result)
            
    def handle_is_palindrome(self, num: int) -> tuple[APIResponse, bytes]:
        str_num = str(num)
        is_palindrome = str_num == str_num[::-1]

        return APIResponse.IS_PALINDROME, struct.pack(BOOL_RESPONSE_FORMAT, is_palindrome)

    def handle_is_primary(self, num: int) -> tuple[APIResponse, bytes]:
        is_prime = True
        
        if num <= 1:
            is_prime = False
        else:
            for i in range(2, int(num**0.5) + 1):
                if num % i == 0:
                    is_prime = False  # If the number is divisible by any integer, it's not prime
                    break
    
        return APIResponse.IS_PRIMARY, struct.pack(BOOL_RESPONSE_FORMAT, is_prime)
                    
        
def main():
    logging.basicConfig(level=logging.DEBUG)
    
    port = DEFAULT_PORT
    if len(sys.argv) < 2:
        print("missing users credentials file argument.")
    if len(sys.argv) >= 3:
        port = sys.argv[2]
    user_cred_file = sys.argv[1]
    
    numServer = Server(user_cred_file)
    numServer.start()


if __name__ == "__main__":
    main()
