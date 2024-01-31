#! /usr/bin/env python3

import sys

from numbers_API import DEFAULT_PORT, APIRequest, NumAPIClient, NumServerException, str_to_MathOp

DEFAULT_HOST = "localhost"
COMMAND_SEP = ": "

WELCOME_MSG = "Welcome! Please log in."
LOGIN_SUCCESS_MSG = "Hi {}, good to see you."
LOGIN_FAIL_MSG = "Failed to login."

def client_loop(numClient: NumAPIClient):
    while True:
        cmd, args = input().split(COMMAND_SEP, 1)

        try:
            if cmd == "User":
                username = args
                cmd, password = input().split(COMMAND_SEP, 1)
                if cmd != "Password":
                    print("Invalid command format!")
                    sys.exit(1)
                    
                auth, auth_user = numClient.auth(username, password)
                if auth and auth_user == username:
                    print(LOGIN_SUCCESS_MSG.format(auth_user))
                else:
                    print(LOGIN_FAIL_MSG)
            elif cmd == "calculate":
                x, op, y = args.split()
                math_op = str_to_MathOp(op)
                res = numClient.calculate(math_op, int(x), int(y))
                print(f"response: {res}.")
            elif cmd == "is_palindrome" or cmd == "is_primary":
                num = int(args)
                res = numClient.is_palindrome(num) if cmd == "is_palindrome" else numClient.is_primary(num)
                res_str = "Yes" if res else "No"
                print(f"response: {res_str}.")
            elif cmd == "quit":
                break
            else:
                print("Invalid command format!")
                break
        except NumServerException as e:
            print(e)
            break
  

def main():
    host = DEFAULT_HOST
    port = DEFAULT_PORT
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = sys.argv[2]

    numClient = NumAPIClient()
    connected = numClient.connect(host, port)
    if not connected:
        print("Failed to connect to the server.")
        sys.exit(1)
        
    print(WELCOME_MSG)
    client_loop(numClient)
    numClient.close()      

if __name__ == "__main__":
    main()
