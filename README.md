# 'numbers' APP Protocol
'numbers' is a simple math server-client application protocol over the tcp protocol.

The protocol is (mostly) a **binary protocol**, using agreed message schema.

The protocol allows simple client authentication using username & password.

Please visit the repo for better README visualization: [link](https://github.com/ofekzohar1/Computer-Networks-HW1).

## Protocol Message Schema

<table class="tg">
<thead>
  <tr>
    <th class="tg-7btt" colspan="3">Protocol Header</th>
    <th class="tg-7btt">Payload</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-c3ow">1st Byte</td>
    <td class="tg-c3ow">2nd Byte</td>
    <td class="tg-c3ow">3rd Byte</td>
    <td class="tg-c3ow">Rest of Bytes</td>
  </tr>
  <tr>
    <td class="tg-c3ow">Request ID</td>
    <td class="tg-c3ow" colspan="2">Payload length in bytes<br>(network byte-order)</td>
    <td class="tg-c3ow">payload in bytes (request arguments)</td>
  </tr>
</tbody>
</table>

The protocol header contains of fixed 3 bytes:
* 1st byte: request type (support up to 256 OPs).
* 2nd+3rd bytes: payload length in bytes, which can be varied depends on the request type.
    * Thus the maximum msg size is 3+2^16=65539 (header size + max payload)
* The protocol can be **extended** easily, if necessary, by adding special request type adding more header bytes, and still be compatible with the old protocol.
* All numbers in the msg encoded into network Byte-order (e.g payload_length, num argument)

## Protocol Supported Requests (client->server)

| request name | request ID | description | payload format | payload length |
| -- | -- | -- | -- | -- | 
| auth | 10 | Authentication with username and password | username[\t]password | variable |
| calculate | 11 | Calculate a simple math operation between two operands (num1 op num2) | [op,num1,num2] | Byte + 2 Ints = 9 |
| is_palindrome | 12 | Checks whether num is a palindrome | [unsigned num] | 16 bytes (128 bits) |
| is_primary | 13 | Checks whether num is a prime number | [unsigned num] | 16 bytes (128 bits) |

* The auth request is the only request with variable payload length (all others are fixed, so **payload_length in header is redundant**).
* The auth request using **Tab char [\t]** to separate between username and password strings.
* is_X requests support unsigned numbers up to 128 bits (computation complexity, can be extended in future protocol).
* Request IDs 0-9 are reserved for system requests.

### The 'calculate' request

The calculate request payload consists of 3 arguments in the following format:

| 1st Byte | 2-5 bytes | 6-9 bytes |
| -- | -- | -- |
| math operation type | 1st operand | 2nd operand |

The supported math operations are:

| Math Operation | op ID |
| -- | -- |
| Addition (+) | 0 |
| Subtraction (-) | 1 |
| Multiplication (x) | 2 |
| Division (/) | 3 |

## Protocol Supported Responses (server->client)

| response name | response ID | description | payload format | payload length |
| -- | -- | -- | -- | -- |
| error | 0 | An error occurred during the client request | [error_ID] | 1 Byte |
| connected | 1 | A connected to a 'numbers' server response | - | 0 Bytes |
| auth | 10 | Authentication response | [username_string] | variable |
| calculate | 11 | Calculate result (num1 op num2) | [float] | 4 Bytes |
| is_palindrome | 12 | is_palindrome response | [bool] | 1 Byte |
| is_primary | 13 | is_primary response | [bool] | 1 Byte |

* If authentication has filed, username_string is the empty string [""], thus **payload length is 0!**
* The auth response is the only response with variable payload length (all others are fixed, so **payload_length in header is redundant**).
* Response IDs 0-9 are reserved for system requests.

### Error types

| error name | error ID | description |
| -- | -- | -- |
| UNEXPECTED | 0 | An unexpected error occurred during client request |
| UNSUPPORTED REQUEST | 1 | The client request type (ID) is unsupported (e.g out of the known IDs) |
| INVALID FORMAT | 2 | The client sent an invalid msg (not complying with the protocol, e.g - too long msg) |
| UNAUTHENTICATD CLIENT | 3 | The client tried to send a request before authenticated to the server |
| INVALID ARGUMENT | 4 | The client sent a valid request with invalid arguments (e.g division be zero - calculate["/", 1, 0]) |
