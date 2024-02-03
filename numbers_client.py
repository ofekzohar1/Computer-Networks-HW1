#! /usr/bin/env python3
"""
Instantiation of 'numbers' client using the numbers_api.
Made by Ofek Zohar (312490402).
"""

import sys
import numbers_api as numAPI

################################ Constants ################################

DEFAULT_HOST = "localhost"  # The default host the client connects to
COMMAND_SEP = ": "  # User input separator (command[sep]arguments)

WELCOME_MSG = "Welcome! Please log in."
LOGIN_SUCCESS_MSG = "Hi {}, good to see you."
LOGIN_FAIL_MSG = "Failed to login."

def main():
    host = DEFAULT_HOST
    port = numAPI.DEFAULT_PORT
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])

    numClient = numAPI.NumAPIClient()
    connected = numClient.connect(host, port)
    if not connected:
        print("Failed to connect to the server.")
        sys.exit(1)

    print(WELCOME_MSG)
    client_loop(numClient)
    numClient.close()

def client_loop(numClient: numAPI.NumAPIClient):
    while True:
        cmd, args = string_cut(input())

        try:
            if cmd == "User":
                username = args
                cmd, password = string_cut(input())
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
                math_op = numAPI.MathOp.str_to_MathOp(op)
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
        except numAPI.NumServerError as e:
            print(e)
            break

def string_cut(s: str, sep: str=COMMAND_SEP) -> tuple[str, str]:
    tokens = s.split(sep, 1)
    if len(tokens) < 2:
        return s, ""
    return tokens[0], tokens[1]

if __name__ == "__main__":
    main()
