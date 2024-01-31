import socket
import struct
from enum import Enum
from typing import Any

DEFAULT_PORT = 1337
AUTH_SEP = "\t"

API_HEADER = "!BH"
API_HEADER_SIZE = struct.calcsize(API_HEADER)
CALCULATE_REQ_FORMAT = "!Bii"
CALCULATE_RESPONSE_FORMAT = "!f"
BOOL_RESPONSE_FORMAT = "!?"
MAX_NUM_BYTES = 16

class APIRequest(Enum):
    AUTH = 10
    CALCULATE = 11
    IS_PALINDROME = 12
    IS_PRIMARY = 13

class APIResponse(Enum):
    ERROR = 0
    CONNECTED = 1
    AUTH = APIRequest.AUTH.value
    CALCULATE = APIRequest.CALCULATE.value
    IS_PALINDROME = APIRequest.IS_PALINDROME.value
    IS_PRIMARY = APIRequest.IS_PRIMARY.value


class MathOp(Enum):
    ADD = 0
    SUB = 1
    MUL = 2
    DIV = 3

class APIError(Enum):
    UNEXPECTED = 0
    UNSUPPORTED_REQUEST = 1
    INVALID_FORMAT = 2
    UNAUTH_CLIENT = 3
    INVALID_ARGUMENT = 4

    @property
    def binary_value(self) -> bytes:
        return self.value.to_bytes(1, byteorder='big')

class NumServerException(Exception):
    pass

def str_to_MathOp(op: str) -> MathOp:
    if op == "+":
        return MathOp.ADD
    elif op == "-":
        return MathOp.SUB
    elif op == "x" or op == "*":
        return MathOp.MUL
    elif op == "/":
        return MathOp.DIV

    return None


class NumAPIClient:
    def connect(self, host: str, port: str=DEFAULT_PORT) -> bool:
        self.client_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_soc.connect((host, port))
        
        res_id, _ = self._recvall()
        if res_id is not APIResponse.CONNECTED:
            self.close()
            return False
        
        return True


    def close(self):
        self.client_soc.close()
        self.client_soc = None

    def _sendall(self, req_id: APIRequest, payload: bytes, length: int=0):
        msg = struct.pack(API_HEADER, req_id.value, length) + payload
        self.client_soc.sendall(msg)

    def _recvall(self) -> tuple[APIResponse, bytes]:
        buffer = b""
        res_msg_len = -1
        while True:
            buffer += self.client_soc.recv(1024)
            if res_msg_len == -1:
                res_msg_len = required_res_length(buffer)
            if len(buffer) == res_msg_len:
                res_id, _ = struct.unpack(API_HEADER, buffer[:API_HEADER_SIZE])
                payload = buffer[API_HEADER_SIZE:]
                return APIResponse(res_id), payload

    def _send_and_recv_all(self, req_id: APIRequest, payload: bytes, length: int=0) -> tuple[APIResponse, bytes]:
        self._sendall(req_id, payload, length)
        res_id, response = self._recvall()
        if res_id is APIResponse.ERROR:
            error = APIError(int.from_bytes(response, byteorder='big'))
            raise NumServerException(f"Server error: {error.name}.")
        if res_id.value != req_id.value:
            raise NumServerException("Response type doesn't match request type.")
        return res_id, response
    
    def auth(self, username: str, password: str) -> tuple[bool, str]:
        msg = AUTH_SEP.join([username, password])
        payload = msg.encode()
        _, response = self._send_and_recv_all(APIRequest.AUTH, payload, len(payload))
        username = response.decode()
        
        is_auth = len(username) > 0
        return is_auth, username

    def calculate(self, op: MathOp, num1: int, num2: int) -> float:
        payload = struct.pack(CALCULATE_REQ_FORMAT, op.value, num1, num2)
        _, response = self._send_and_recv_all(APIRequest.CALCULATE, payload, len(payload))
        
        result = struct.unpack(CALCULATE_RESPONSE_FORMAT, response)[0]
        return result
    

    def is_palindrome(self, num: int) -> bool:
        return self._is_request(APIRequest.IS_PALINDROME, num)

    def is_primary(self, num: int) -> bool:
        return self._is_request(APIRequest.IS_PRIMARY, num)

    def _is_request(self, req_id: APIRequest, num: int) -> bool:
        num = abs(num)
        payload = num.to_bytes(MAX_NUM_BYTES, byteorder="big")
        _, response = self._send_and_recv_all(req_id, payload, MAX_NUM_BYTES)
        
        result = struct.unpack(BOOL_RESPONSE_FORMAT, response)[0]
        return result

def unpack_req(msg_buffer: bytes) -> (APIRequest, list[Any]):
    req_id, _ = struct.unpack(API_HEADER, msg_buffer[:API_HEADER_SIZE])
    req_id = APIRequest(req_id)

    payload = msg_buffer[API_HEADER_SIZE:]
    args = []

    if req_id is APIRequest.AUTH:
        args += payload.decode().split(AUTH_SEP)
    elif req_id is APIRequest.CALCULATE:
        args += list(struct.unpack(CALCULATE_REQ_FORMAT, payload))
        args[0] = MathOp(args[0])
    elif req_id is APIRequest.IS_PALINDROME or req_id is APIRequest.IS_PRIMARY:
        args.append(int.from_bytes(payload, byteorder="big"))

    return req_id, args

def required_req_length(req_msg_buffer: bytes) -> int:
    if not req_msg_buffer or len(req_msg_buffer) < API_HEADER_SIZE:
        return -1
    
    req_id, payload_len = struct.unpack(API_HEADER, req_msg_buffer[:API_HEADER_SIZE])
    req_id = APIRequest(req_id)

    msg_length = API_HEADER_SIZE
    if req_id is APIRequest.AUTH:
        msg_length += payload_len
    elif req_id is APIRequest.CALCULATE:
        msg_length += struct.calcsize(CALCULATE_REQ_FORMAT)
    elif req_id is APIRequest.IS_PALINDROME or req_id is APIRequest.IS_PRIMARY:
        msg_length += MAX_NUM_BYTES

    return msg_length

def required_res_length(res_msg_buffer: bytes) -> int:
    if not res_msg_buffer or len(res_msg_buffer) < API_HEADER_SIZE:
        return -1
    
    res_id, payload_len = struct.unpack(API_HEADER, res_msg_buffer[:API_HEADER_SIZE])
    res_id = APIResponse(res_id)

    msg_length = API_HEADER_SIZE
    if res_id is APIResponse.AUTH:
        msg_length += payload_len
    elif res_id is APIResponse.CALCULATE:
        msg_length += struct.calcsize(CALCULATE_RESPONSE_FORMAT)
    elif res_id is APIResponse.IS_PALINDROME or res_id is APIResponse.IS_PRIMARY:
        msg_length += 1 # boolean payload
    elif res_id is APIResponse.ERROR:
        msg_length += payload_len


    return msg_length