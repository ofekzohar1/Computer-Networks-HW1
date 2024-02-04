"""
Python implementation for the 'numbers' service API.
Made by Ofek Zohar (312490402).
"""

import socket
import struct
from enum import Enum
from typing import Any, Tuple, List

################################ Constants ################################

DEFAULT_PORT = 1337  # The default 'numbers' server listening port
AUTH_SEP = "\t"  # The user credentials separator (username[sep]password)
DEFAULT_BYTES_RECV = 1024  # Default number of bytes to read.

API_HEADER = "!BH"  # The protocol header - (ubyte, ushort) in network byte-order
API_HEADER_SIZE = struct.calcsize(API_HEADER)  # The protocol header size in bytes
CALCULATE_REQ_FORMAT = "!Bii"  # Calculate request packing format (ubyte, int, int)
CALCULATE_RESPONSE_FORMAT = "!f"  # Calculate response packing format (float)
BOOL_RESPONSE_FORMAT = "!?"  # Boolean response packing format (bool)
MAX_NUM_BYTES = 16  # Maximum number of bytes for is_ type requests (128 bit numbers)

################################ Enums ################################

class APIRequest(Enum):
    """Enum for a 'numbers' API request type.
        0-9 reserved for system requests."""
    AUTH = 10
    CALCULATE = 11
    IS_PALINDROME = 12
    IS_PRIMARY = 13

class APIResponse(Enum):
    """Enum for a 'numbers' API response type (matching the requests).
        0-9 reserved for system response."""
    ERROR = 0  # Error response
    CONNECTED = 1  # A connected successfully response
    AUTH = APIRequest.AUTH.value
    CALCULATE = APIRequest.CALCULATE.value
    IS_PALINDROME = APIRequest.IS_PALINDROME.value
    IS_PRIMARY = APIRequest.IS_PRIMARY.value

class MathOp(Enum):
    """Enum for a calculate request allowed math operations."""
    ADD = 0
    SUB = 1
    MUL = 2
    DIV = 3

    @staticmethod
    def str_to_MathOp(op: str) -> 'MathOp':
        """Return the MathOp object correspond to the provided string.

        Args:
            op (`str`): The provided math operation in str representation.

        Returns:
            MathOp: The correspond operation.
        """
        if op == "+":
            return MathOp.ADD
        if op == "-":
            return MathOp.SUB
        if op == "x" or op == "*":
            return MathOp.MUL
        if op == "/":
            return MathOp.DIV

        return None

class APIError(Enum):
    """Enum for a 'numbers' API error type."""
    UNEXPECTED = 0  # Unexpected server error
    UNSUPPORTED_REQUEST = 1  # Unsupported request type (Not mentioned in the Readme API doc)
    INVALID_FORMAT = 2  # Invalid msg format (As mentioned in the Readme API doc)
    UNAUTH_CLIENT = 3  # Unauthenticated client trying to reach the server operations
    INVALID_ARGUMENT = 4  # Invalid request arguments (e.g 'calculate: 1 / 0', can't divide by zero)

    @property
    def binary_value(self) -> bytes:
        """bytes: The error value in bytes (network byte-order)"""
        return self.value.to_bytes(1, byteorder='big')  # currently only 1 byte is needed

################################ Errors ################################

class NumServerError(Exception):
    """NumServerError class is a custom-made 'numbers' server exception.

    Args:
        error_num (:obj:`int`): The error number describing the error type (Mentioned in Readme).
        msg (:obj:`str`): Additional error message. Default to "".
    """
    def __init__(self, error_num: int, msg: str="") -> None:
        try:
            api_err = APIError(error_num)
        except ValueError:  # Invalid error number, default to unexpected
            api_err = APIError.UNEXPECTED

        full_msg = f"Server error ({api_err.name})"
        full_msg += f": {msg}" if msg else "."  # Add the msg if provided
        super().__init__(full_msg)

################################ Classes ################################

class NumAPIClient:
    """NumAPIClient class represent a client object implementing the API.

    Args:
        client_soc (:obj:`socket.socket`): The socket connection to the server.
    """
    def __init__(self) -> None:
        self.client_soc = None

    def connect(self, host: str, port: str=DEFAULT_PORT) -> bool:
        """Connects to the 'numbers' server in (host:port).
        Succeeded if the server sends a connected msg.

        Args:
            host (str): The server's host ip/name.
            port (str, optional): The server's listening port. Defaults to DEFAULT_PORT.

        Returns:
            bool: True if connected successfully.
        """
        self.client_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_soc.connect((host, port))
            res_id, _ = self._recvall()
        except socket.error:  # Connection error, set the response to ERROR for the right handling
            res_id = APIResponse.ERROR

        # Disconnect from the server if not a connected response
        if res_id is not APIResponse.CONNECTED:
            self.close()
            return False

        return True

    def close(self):
        """Close the connection to the server.
        """
        self.client_soc.close()
        self.client_soc = None

    def auth(self, username: str, password: str) -> Tuple[bool, str]:
        """Authentication request to the server.

        Args:
            username (`str`): The input username.
            password (`str`): The input password.

        Raises:
            `NumServerError`: Connection issue or API error.

        Returns:
            Tuple[`bool`, `str`]: (True, username) if succeeded, otherwise (False, "").
        """
        # concat username and password separated by AUTH_SEP
        msg = AUTH_SEP.join([username, password])

        payload = msg.encode()
        _, response = self._send_and_recv_all(APIRequest.AUTH, payload, len(payload))
        username = response.decode()  # Decode the payload to string

        is_auth = len(username) > 0  # No payload means auth failed!
        return is_auth, username

    def calculate(self, op: MathOp, num1: int, num2: int) -> float:
        """Calculate request to the server (num1 op num2).

        Args:
            op (`MathOp`): The math operation to apply.
            num1 (`int`): The first operand.
            num2 (`int`): The second operand.

        Raises:
            `NumServerError`: Connection issue or API error.

        Returns:
            `float`: The calculation result.
        """
        payload = struct.pack(CALCULATE_REQ_FORMAT, op.value, num1, num2)
        _, response = self._send_and_recv_all(APIRequest.CALCULATE, payload, len(payload))

        result = struct.unpack(CALCULATE_RESPONSE_FORMAT, response)[0]  # (res,)[0] == res
        return result

    def is_palindrome(self, num: int) -> bool:
        """'Is num a palindrome?' request to the server.

        Args:
            num (`int`): The number in question.

        Raises:
            `NumServerError`: Connection issue or API error.

        Returns:
            `bool`: True if the provided number is a palindrome.
        """
        return self._is_request(APIRequest.IS_PALINDROME, num)

    def is_primary(self, num: int) -> bool:
        """'Is num is a prime number?' request to the server.

        Args:
            num (`int`): The number in question.

        Raises:
            `NumServerError`: Connection issue or API error.

        Returns:
            `bool`: True if the provided number is a prime number.
        """
        return self._is_request(APIRequest.IS_PRIMARY, num)

    def _is_request(self, req_id: APIRequest, num: int) -> bool:
        """Is_ requests wrapper

        Args:
            req_id (`APIRequest`): The request type.
            num (`int`): The number in question.

        Raises:
            `NumServerError`: Connection issue or API error.

        Returns:
            `bool`: True if the is_X(num) response is True.
        """
        num = abs(num)  # Is request doesn't affected by the sign.
        payload = num.to_bytes(MAX_NUM_BYTES, byteorder="big")
        _, response = self._send_and_recv_all(req_id, payload, MAX_NUM_BYTES)

        result = struct.unpack(BOOL_RESPONSE_FORMAT, response)[0]  # (res,)[0] == res
        return result

    def _sendall(self, req_id: APIRequest, payload: bytes, length: int=0):
        """Send the whole request msg to the server.

        Args:
            req_id (`APIRequest`): request type.
            payload (`bytes`): The request payload (packed arguments).
            length (`int`, optional): The payload's length (if relevant). Defaults to 0.

        Raises:
            `NumServerError`: Connection issue.
        """
        msg = struct.pack(API_HEADER, req_id.value, length) + payload
        try:
            print("before send")
            self.client_soc.sendall(msg)
            print("after send")
        except socket.error:
            print("catch error")
            raise NumServerError(APIError.UNEXPECTED, "Disconnected from server.")

    def _recvall(self) -> Tuple[APIResponse, bytes]:
        """Recv the whole response msg from the server.

        Raises:
            `NumServerError`: Connection issue or unrecognized response type.

        Returns:
            Tuple[`APIResponse`, `bytes`]: (response type, response payload)
        """
        buffer = b""
        res_msg_len = -1  # Flag: before reading the header.
        try:
            while True:  # As long as there are bytes to read
                # Bytes left to read. If unknown, use DEFAULT_BYTES_RECV.
                bytes_to_read = res_msg_len - buffer if res_msg_len != -1 else DEFAULT_BYTES_RECV

                buffer += self.client_soc.recv(bytes_to_read)
                if res_msg_len == -1:
                    res_msg_len = required_res_length(buffer)  # Get the right msg length

                if len(buffer) == res_msg_len:  # EOF, response received
                    res_id, _ = struct.unpack(API_HEADER, buffer[:API_HEADER_SIZE])
                    payload = buffer[API_HEADER_SIZE:]
                    return APIResponse(res_id), payload

        except ValueError:  # Unrecognized response type
            raise NumServerError(APIError.INVALID_FORMAT.value, "Unrecognized response type.")
        except socket.error:  # Connection issue
            raise NumServerError(APIError.UNEXPECTED, "Disconnected from server.")

    def _send_and_recv_all(self, req_id: APIRequest, payload: bytes, length: int=0) -> Tuple[APIResponse, bytes]:
        """Send request & Receive response wrapper.

        Args:
            req_id (`APIRequest`): request type.
            payload (`bytes`): The request payload (packed arguments).
            length (`int`, optional): The payload's length (if relevant). Defaults to 0.

        Raises:
            `NumServerError`: Connection issue or unrecognized response type.

        Returns:
            Tuple[`APIResponse`, `bytes`]: (response type, response payload)
        """
        self._sendall(req_id, payload, length)
        res_id, response = self._recvall()

        if res_id is APIResponse.ERROR:  # Get error msg from the server
            error_num = int.from_bytes(response, byteorder='big')  # unpack the error type
            raise NumServerError(error_num)
        if res_id.value != req_id.value:  # Unmatched request and response types
            raise NumServerError(APIError.UNEXPECTED.value, "Response type doesn't match request type.")
        return res_id, response

################################ Handlers ################################

def unpack_req(msg_buffer: bytes) -> Tuple[APIRequest, List[Any]]:
    """Unpack the request bytes message.

    Args:
        `msg_buffer` (bytes): The buffer containing the message.

    Raises:
        `NumServerError`: Unsupported request type.

    Returns:
        Tuple[`APIRequest`, List[`Any`]]: (request type, [arguments list])
    """
    req_id, _ = struct.unpack(API_HEADER, msg_buffer[:API_HEADER_SIZE])
    try:
        req_id = APIRequest(req_id)
    except ValueError:  # Unsupported request type
        raise NumServerError(APIError.UNSUPPORTED_REQUEST.value)

    payload = msg_buffer[API_HEADER_SIZE:]

    # Unpack the request arguments
    args = []
    if req_id is APIRequest.AUTH:
        args += payload.decode().split(AUTH_SEP)  # Separate username and password
    elif req_id is APIRequest.CALCULATE:  # unpack to [op, num1, num2]
        args += list(struct.unpack(CALCULATE_REQ_FORMAT, payload))
        try:
            args[0] = MathOp(args[0])
        except ValueError:  # Unsupported math operation
            raise NumServerError(APIError.INVALID_ARGUMENT, "Unsupported math operation.")

    elif req_id is APIRequest.IS_PALINDROME or req_id is APIRequest.IS_PRIMARY:
        args.append(int.from_bytes(payload, byteorder="big"))

    return req_id, args

def required_req_length(req_msg_buffer: bytes) -> int:
    """Get the correct request msg length according to the protocol.

    Args:
        req_msg_buffer (`bytes`): The buffer containing the message. 

    Raises:
        `NumServerError`: Unsupported request type.

    Returns:
        `int`: The correct message length in bytes. If unknown, return -1.
    """
    # Buffer is empty or the buffer doesn't contain the API header.
    if not req_msg_buffer or len(req_msg_buffer) < API_HEADER_SIZE:
        return -1

    req_id, payload_len = struct.unpack(API_HEADER, req_msg_buffer[:API_HEADER_SIZE])
    try:
        req_id = APIRequest(req_id)
    except ValueError:  # Unsupported request type
        raise NumServerError(APIError.UNSUPPORTED_REQUEST.value)

    msg_length = API_HEADER_SIZE  # The basic msg length
    if req_id is APIRequest.AUTH:
        msg_length += payload_len  # Length according to the payload_len header attribute.

    # Below are fixed sizes!
    elif req_id is APIRequest.CALCULATE:
        msg_length += struct.calcsize(CALCULATE_REQ_FORMAT)
    elif req_id is APIRequest.IS_PALINDROME or req_id is APIRequest.IS_PRIMARY:
        msg_length += MAX_NUM_BYTES

    return msg_length

def required_res_length(res_msg_buffer: bytes) -> int:
    """Get the correct response msg length according to the protocol.

    Args:
        req_msg_buffer (`bytes`): The buffer containing the message. 

    Raises:
        `NumServerError`: Unsupported request type.

    Returns:
        `int`: The correct message length in bytes. If unknown, return -1.
    """
    # Buffer is empty or the buffer doesn't contain the API header.
    if not res_msg_buffer or len(res_msg_buffer) < API_HEADER_SIZE:
        return -1

    res_id, payload_len = struct.unpack(API_HEADER, res_msg_buffer[:API_HEADER_SIZE])
    try:
        res_id = APIResponse(res_id)
    except ValueError:  # Unrecognized response type
        raise NumServerError(APIError.INVALID_FORMAT.value, "Unrecognized response type.")

    msg_length = API_HEADER_SIZE
    if res_id is APIResponse.AUTH or res_id is APIResponse.ERROR:
        msg_length += payload_len  # Length according to the payload_len header attribute.

    # Below are fixed sizes!
    elif res_id is APIResponse.CALCULATE:
        msg_length += struct.calcsize(CALCULATE_RESPONSE_FORMAT)
    elif res_id is APIResponse.IS_PALINDROME or res_id is APIResponse.IS_PRIMARY:
        msg_length += 1 # boolean payload

    return msg_length
