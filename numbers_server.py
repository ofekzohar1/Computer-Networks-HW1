#! /usr/bin/env python3
"""
Instantiation of 'numbers' server using the numbers_API.
Made by Ofek Zohar (312490402).
"""

import signal
import socket
import select
import struct
import sys
import logging
from typing import Tuple

from numbers_API import API_HEADER, AUTH_SEP, APIError, APIRequest, APIResponse, MathOp
import numbers_API as numAPI

################################ Constants ################################

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 1337

################################ Classes ################################

class OnlineClient:
    """OnlineClient class represent an online client connection.

    Args:
        soc (:obj:`socket.socket`): The client socket.
        peer (:obj:`str`): The client peer name.
        buffer (:obj:`bytes`): messages buffer.
        msg_length (:obj:`int`): The current msg_length. -1 flags an unread message.
        is_auth (:obj:`bool`): Is the client authenticated with username and password. Default to False.
    """
    def __init__(self, soc: socket.socket, peer: str) -> None:
        self.soc = soc
        self.peer = peer
        self.buffer = bytes()
        self.msg_length = -1
        self.is_auth = False

class Server:
    """Server class represents a server object supporting the API.

    Args:
        listening_host (:obj:`str`): The server's host ip/name.
        listening_port (:obj:`str`): The server's listen port.
        listen_soc (:obj:`socket.socket`): The server listen socket.
        user_credentials_file (:obj:`str`): The path to the users credentials file.
        user_credentials (Dict[`str`, `str`]): username->password data structure.
        client_sockets (Dict[`socket.socket`, `OnlineClient`]): Maintain online clients. socket->OnlineClient data structure. 
    """
    def __init__(self, user_credentials_file, listening_host=DEFAULT_HOST, listening_port=DEFAULT_PORT) -> None:
        self.listening_host = listening_host
        self.listening_port = listening_port
        self.listen_soc = None
        self.user_credentials_file = user_credentials_file
        self.user_credentials = {}
        self.client_sockets = {}

    def read_user_cred_from_file(self):
        """Read users credentials from file."""
        try:
            with open(self.user_credentials_file, "r", encoding="utf-8") as file:
                for line in file:
                    username, password = line.strip().split(AUTH_SEP)
                    self.user_credentials[username] = password
                    
        except FileNotFoundError:
            logging.error("Error: File '%s' not found.", self.user_credentials_file)
            sys.exit(1)
        except Exception as e:
            logging.error("Error loading user credentials from file: %s.", e)
            sys.exit(1)

        logging.debug("Successfully read user credentials.")

    def stop(self):
        """Stop server cleanly by closing online sockets."""
        self.listen_soc.close()
        self.client_sockets.pop(self.listen_soc)
        logging.info("Server stopped listening.")
        
        for soc in self.client_sockets:
            logging.debug("Closing connection to %s.", soc.getpeername())
            soc.close()
        logging.info("Server has stopped.")


    def start(self):
        """Start the 'numbers' server."""
        logging.info("Server starting...")

        # Read users credentials from file.
        self.read_user_cred_from_file()

        # Create a listening TCP socket
        self.listen_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow port reuse

        try:
            # Bind the socket to a specific address and port
            self.listen_soc.bind((self.listening_host, self.listening_port))

            # Listen for incoming connections (max 5 connections in the backlog)
            self.listen_soc.listen(5)
            logging.info("Server listening on %s:%s.", self.listening_host, self.listening_port)
        except socket.error:
            logging.error("Error listening on %s:%s.", self.listening_host, self.listening_port)
            sys.exit(1)

        # Dict to keep track of online client sockets (Include the unique listen socket)
        self.client_sockets[self.listen_soc] = None

        # Start accept & serve clients
        self.server_loop()

    def server_loop(self):
        """The server loop. Get clients requests & handle the response."""
        logging.info("Inside server loop. server is up!")

        while True:
            # Use select to wait for any of the sockets to be ready for processing
            readable, _, _ = select.select(self.client_sockets.keys(), [], [])

            for soc in readable:  # Handle all read-ready sockets
                if soc == self.listen_soc:  # Incoming new client connection
                    self.accept_new_client()
                else:  # Existing client socket, receive and process request
                    client = self.client_sockets[soc]
                    try:
                        # Bytes left to read. If unknown, use DEFAULT_BYTES_RECV.
                        bytes_to_read = client.msg_length - client.buffer if client.msg_length != -1 else numAPI.DEFAULT_BYTES_RECV
                        data = soc.recv(bytes_to_read)
                    except socket.error as e:  # Connection to client issue
                        logging.debug("Error receiving data from %s: %s.", client.peer, e)
                        self.disconnect_client(client)
                        continue  # Skip to next client

                     # Connection closed by the client or too many bytes received
                    if not data or (client.msg_length != -1 and len(data)+len(client.buffer) > client.msg_length):
                        self.disconnect_client(client)
                        continue

                    client.buffer += data
                    if client.msg_length == -1: # New message/Header yet received
                        client.msg_length = numAPI.required_req_length(client.buffer)

                    if len(client.buffer) == client.msg_length:  # EOF, request received
                        response = self.handle_req(client)

                        if not response:  # Didn't get any valid request
                            self.disconnect_client(client)
                            continue

                        try:
                            soc.sendall(response)  # send response

                            # Clear the buffer
                            client.msg_length = -1
                            client.buffer = b""
                        except socket.error as e:  # Connection to client issue
                            logging.debug("Error sending data from %s: %s.", client.peer, e)
                            self.disconnect_client(client)

    def accept_new_client(self):
        """Accept new client. If succeeded send a connected response to the client."""
        try:
            # New connection waiting in queue
            client_socket, client_address = self.listen_soc.accept()

            # Send a connected message to the client
            self.send_connected_msg(client_socket)

        except socket.error as e:  # Connection to client issue
            logging.debug("Error accepting new connection: %s.", e)
            client_socket.close()
            return

        # Add the new client socket to the data structure
        self.client_sockets[client_socket] = OnlineClient(client_socket, client_address)
        logging.info("Accepted connection from %s.", client_address)

    def disconnect_client(self, client: OnlineClient):
        """Disconnect an existing online client.

        Args:
            client (`OnlineClient`): The client to disconnect from.
        """
        logging.info("Closing connection to %s.", client.peer)
        client.soc.close()
        self.client_sockets.pop(client.soc)

    def send_connected_msg(self, soc: socket.socket):
        """Send a connected msg to the provided socket.

        Args:
            soc (`socket.socket`): The socket to send the msg to.
        """
        connected_msg = struct.pack(API_HEADER, APIResponse.CONNECTED.value, 0)
        soc.sendall(connected_msg)

    def handle_req(self, client: OnlineClient) -> bytes:
        """Handle requests function wrapper.

        Args:
            client (`OnlineClient`): The client requestor.

        Returns:
            bytes: The response.
        """
        try:
            # Unpack the client request
            req_id, args = numAPI.unpack_req(client.buffer)
        except Exception:  # Error during unpacking, send error response
            payload = APIError.INVALID_FORMAT.binary_value # Invalid request format
            return struct.pack(API_HEADER, APIResponse.ERROR.value, len(payload)) + payload

        if req_id is not APIRequest.AUTH and not client.is_auth:  # Unauthenticated client error
            payload = APIError.UNAUTH_CLIENT.binary_value
            return struct.pack(API_HEADER, APIResponse.ERROR.value, len(payload)) + payload

        # The wrapper
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

    def handle_auth(self, client: OnlineClient, username: str, password: str) -> Tuple[APIResponse, bytes]:
        """Auth request handler. If auth succeeded response the authed username.

        Args:
            client (`OnlineClient`): The client requestor.
            username (`str`): The input username.
            password (`str`): The input password.

        Returns:
            Tuple[APIResponse, bytes]: (response type, response msg). If request failed (ERROR, ERROR TYPE).
        """
        payload = b""
        if username in self.user_credentials and self.user_credentials[username] == password:
            payload = username.encode()
            client.is_auth = True
            logging.info("The client %s authenticated with '%s'.", client.peer, username)
        else:
            logging.debug("The client %s failed login with '%s'.", client.peer, username)
            client.is_auth = False

        return APIResponse.AUTH, payload

    def handle_calculate(self, op: MathOp, num1: int, num2: int) -> Tuple[APIResponse, bytes]:
        """Calculate request handler (num1 op num2).

        Args:
            op (`MathOp`): The math operation to apply.
            num1 (`int`): The first operand.
            num2 (`int`): The second operand.

        Returns:
            Tuple[`APIResponse`, `bytes`]: (response type, response msg). If request failed (ERROR, ERROR TYPE).
        """
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
        except ArithmeticError:  # e.g division by zero
            return APIResponse.ERROR, APIError.INVALID_ARGUMENT.binary_value

        return APIResponse.CALCULATE, struct.pack(numAPI.CALCULATE_RESPONSE_FORMAT, result)

    def handle_is_palindrome(self, num: int) -> Tuple[APIResponse, bytes]:
        """is palindrome handler. response True if num is a palindrome.

        Args:
            num (`int`): The number in question.

        Returns:
            Tuple[`APIResponse`, `bytes`]: (response type, response msg). If request failed (ERROR, ERROR TYPE).
        """
        str_num = str(num)  # string representation of the number
        is_palindrome = str_num == str_num[::-1]  # num is palindrome iff num == rev(num)

        return APIResponse.IS_PALINDROME, struct.pack(numAPI.BOOL_RESPONSE_FORMAT, is_palindrome)

    def handle_is_primary(self, num: int) -> Tuple[APIResponse, bytes]:
        """is primary handler. response True if num is a prime number.

        Args:
            num (`int`): The number in question.

        Returns:
            Tuple[`APIResponse`, `bytes`]: (response type, response msg). If request failed (ERROR, ERROR TYPE).
        """
        is_prime = True

        if num <= 1:  # Prime number > 1
            is_prime = False
        else:
            for i in range(2, int(num**0.5) + 1):  # Look for any divisors [2, sqrt(num)]
                if num % i == 0:
                    is_prime = False  # If the number is divisible by any integer, it's not prime
                    break

        return APIResponse.IS_PRIMARY, struct.pack(numAPI.BOOL_RESPONSE_FORMAT, is_prime)

################################ Main ################################

num_server = None  # uninitialized server

def signal_handler(signum, frame):
    if num_server is not None:  # server is running
        num_server.stop()
    sys.exit(0)

def main():
    """The server main function."""
    global num_server  # num_server is global to access through signal_handler
    
    # Uncomment below to see the logs in console 
    logging.basicConfig(level=logging.DEBUG)

    # Read cl args
    port = DEFAULT_PORT
    if len(sys.argv) < 2:
        print("missing users credentials file argument.")
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])
    user_cred_file = sys.argv[1]

    # Set SIGINT handler to exit the server cleanly
    signal.signal(signal.SIGINT, signal_handler)

    # Start the server
    num_server = Server(user_cred_file, listening_port=port)
    num_server.start()


if __name__ == "__main__":
    main()
