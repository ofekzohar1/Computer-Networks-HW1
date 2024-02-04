#! /usr/bin/env python3
"""
Instantiation of 'numbers' client using the numbers_API.
Made by Ofek Zohar (312490402).
"""

import sys
import numbers_API as numAPI

################################ Constants ################################

DEFAULT_HOST = "localhost"  # The default host the client connects to
COMMAND_SEP = ": "  # User input separator (command[sep]arguments)

WELCOME_MSG = "Welcome! Please log in."
LOGIN_SUCCESS_MSG = "Hi {}, good to see you."
LOGIN_FAIL_MSG = "Failed to login."

################################ Functions ################################

def main():
    """The client main function."""
    # Read cl arguments
    host = DEFAULT_HOST
    port = numAPI.DEFAULT_PORT
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])

    # Connect to the server
    numClient = numAPI.NumAPIClient()
    connected = numClient.connect(host, port)
    if not connected:  # Connection fail
        print("Failed to connect to the server.")
        sys.exit(1)
    print(WELCOME_MSG)  # Connected successfully
    
    client_loop(numClient)
    numClient.close()  # Disconnect from the server

def client_loop(numClient: numAPI.NumAPIClient):
    """The client loop. Send client requests, print & receive the response.

    Args:
        numClient (`numAPI.NumAPIClient`): The 'numbers' client API object.
    """
    while True:
        cmd, args = string_cut(input())  # Cuts the user input into command part and arguments part

        try:
            if cmd == "User":  # Auth request
                username = args
                cmd, password = string_cut(input())
                if cmd != "Password":  # 'User' cmd must be followed by 'Password'
                    print("Invalid command format!")
                    break

                auth, auth_user = numClient.auth(username, password)  # Send auth req to the server
                if auth and auth_user == username:
                    print(LOGIN_SUCCESS_MSG.format(auth_user))
                else:  # Auth failed
                    print(LOGIN_FAIL_MSG)

            elif cmd == "calculate":
                x, op, y = args.split()  # Split the user input into arguments
                math_op = numAPI.MathOp.str_to_MathOp(op)  # Convert op_str to MathOp object
                if math_op is None:
                    print(f"Invalid command argument: Unsupported math operation '{op}'.")
                    break

                res = numClient.calculate(math_op, int(x), int(y))
                print(f"response: {res}.")

            elif cmd == "is_palindrome" or cmd == "is_primary":
                num = int(args)
                res = numClient.is_palindrome(num) if cmd == "is_palindrome" else numClient.is_primary(num)
                res_str = "Yes" if res else "No"
                print(f"response: {res_str}.")

            elif cmd == "quit":  # Quit from client app, disconnect from server
                break
            else:
                print("Invalid command format!")
                break
        except numAPI.NumServerError as e:  # Server returned an error response
            print(e)
            break

def string_cut(s: str, sep: str=COMMAND_SEP) -> tuple[str, str]:
    """Cuts the provided string into 2 parts around the provided separation chars.

    Args:
        s (`str`): The string to cut.
        sep (`str`, optional): The separator. Defaults to COMMAND_SEP.

    Returns:
        tuple[`str`, `str`]: (before_sep_str, after_sep_str). If s doesn't contain the sep chars, return (s, "").
    """
    tokens = s.split(sep, 1)
    if len(tokens) < 2:
        return s, ""
    return tokens[0], tokens[1]

if __name__ == "__main__":
    main()
