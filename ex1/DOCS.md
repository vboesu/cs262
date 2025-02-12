# Bright-Vincent Chat Documentation

## Overview
This project implements a simple distributed chat application for our Distributed Computing course. The system comprises a TCP server and a `tkinter`-based client. Communication uses a custom binary wire protocol that is efficient, flexible, and easy to extend.

## Architecture
- **Server:**
  The server runs on a single thread and processes requests in the order they arrive. It supports simple user management (account creation, login, deletion, search) and messaging (sending, receiving). Note here in our interface we also added the JSON implementation, so that one can choose to use either our custom BVC (Bright-Vincent-Codec) protocol or the JSON version.
  
- **Client:**  
  A minimalistic GUI client built with `tkinter`. The client sends requests to the server (e.g., create account, login, send message, read messages) and uses a dedicated listener thread to handle responses as a result from requests sent by the client and push notifications from the server, e.g. when receiving a message while online.

## Wire Protocol Design

### Header (Fixed 8 Bytes)
- **Version (1 byte, unsigned):**  
  Set to 1. This allows for future protocol upgrades.
- **Request Code (1 byte, unsigned):**  
  Identifies the operation (e.g., create account, login, send message).
- **Request ID (2 bytes, unsigned, little-endian):**  
  Identifies the request/response.
- **Checksum (2 bytes, unsigned, little-endian):**  
  Computed as the sum of payload bytes modulo 65536. Provides basic error detection.
- **Payload Length (2 bytes, unsigned, little-endian):**  
  Indicates the length (in bytes) of the TLV-encoded payload.

### TLV-Encoded Payload
Each field in the payload is encoded as:
- **Field Type (1 byte):**
  Available types: `int`, `float`, `string`, `bytes`, `list`, `dict`, `bool`, `null`.
- **Field Length (2 bytes, little-endian):**
  Length of **Field Value** in bytes, except for the case of `list` and `dict`, where it refers to the number of items.
- **Field Value (raw bytes):**
  Encoded field value. Uses little-endian for all numeric representations, treats integers as signed, and encoded strings using UTF-8. This part is empty if the field is of type `null`. Encodes `list`s recursively by encoding the contained objects, and encodes `dict`s by recursively encoding keys and values in alternating order.

## Operations
The server supports the following operations, uniquely identified by a string or a corresponding positive integer. Data is sent as key-value pairs, i.e. as a dictionary in Python. Return data (where applicable) is similarly represented as key-value pairs.

Successful requests are returned by the server with the request code `100`, while errors are indicated by the request code `40`. Whenever an operation requires keys, should they not be provided in the request (or be empty), an error is thrown.

1. `username_exists`. Requires key `username`. Returns key `exists` with value `true` if and only if a user with the specified username (case-sensitive) exists.
2. `register`. Requires keys `username` and `password_hash`. Creates an account if none exists with the specified username, otherwise throws an error. Returns key `token` containing a login token to be included in all subsequent communication with the server to prove authorization and provide identification.
3. `login`. Requires keys `username` and `password_hash`. Checks if the password hash matches to the one in the database for the provided username, otherwise throws an error. Returns key `token` containing a login token to be included in all subsequent communication with the server to prove authorization and provide identification.
4. `accounts`. Optional arguments `pattern` which describes a SQL-style wildcard search, `page` which describes the requested page of results, and `per_page` which describes how many results to return per page (up to 100, default value 20). Performs a (wildcard) search over all usernames and returns the usernames which match the search pattern, or all usernames if no pattern is provided. Returns key `items` with list of accounts, key `total_count` indicating the total number of accounts (matching the search pattern if one is provided), key `page`, key `per_page`.
5. `unread_messages`. Optional argument `per_page` which specifies how many undelivered messages to return at once (up to 100, default value 20). Returns up to `per_page` undelivered messages, **starting from the oldest**, and marks them as read at the current timestamp. Returns key `items` with list of unread messages, key `total_count` indicating the total number of undelivered messages (including the ones currently being delivered), key `page`, key `per_page`, both mainly for bookkeeping.
6. `read_messages`. Optional arguments `page` which describes the requested page of messages, and `per_page` which describes how many messages to return per page (up to 100, default value 20). Returns up to `per_page` previously delivered messages, **starting from the newest**.
7. `message`. Requires keys `to` and `content`. Sends a message to recipient with username `to` with content `content` and throws an error if the recipient does not exist or is self. Immediately delivers the message to the recipient if the recipient is also online as a push request. Returns key `message` with the sent message to the sender (which now also includes information like the message ID and timestamp).
8. `delete_messages`. Requires key `messages`, interpreted as list of message IDs (i.e. integers). Deletes the messages if and only if the current user is allowed to delete *all* requested messages, i.e. if the user is either sender or recipient of *all* specified messages. Returns `null`.
9. `delete_account`. Deletes the current user's account. Returns `null`.

## Request/Response and Push Communication
To enable both the classic request/response communication as well as push notifications from the server over the same socket, we implement a central routing and listening system in the client which is responsible for everything that happens with the socket. In some thread (in our case, this is usually the main client thread), a request sent by the client is processed by this socket handler, is given a unique request ID and sent to the server. While setting up the request to send to the server, the socket handler also creates a queue for the response object, which is passed to the sending method as soon as the request has been passed to the server (i.e. without waiting for its response). The sending method can then decide to wait for the response by blocking on the queue or proceed to do computations and revisit the response at some other time.

The separate listener thread then continuously listens for responses from the server. Once it has received any kind of response from the server, whether as a result of a prior request or not, it parses it and then determines based on the request code and the request ID (if one is provided) whether there is a thread waiting for this response or whether this is a push notification from the server (request code `42` corresponds to a push). In the former case, the response is placed in the queue corresponding to the request such that any waiting thread is unblocked and can pick up its work with the response from the server. In the latter case, the response is put into a push queue which stores all of the push notifications.

A separate push thread blocks on the push queue and re-awakens once a push notification has been received. It then processes the push notification according to its type, which in our case is usually identified by the type of content that is sent along with it, although one may also imagine in the future different kinds of push request codes or a use of the `request_id` field as flags etc. to indicate the specific type of push notification.

## Usage
To start the server, run
```
python run.py server --host=[HOST] --port=[PORT] --db-url=[DB_URL]
```
with `[HOST]` and `[PORT]` replaced by your values. You may also use the environment variables `$HOST`, `$PORT` and `$DB_URL` instead of command-line arguments, for example through a `.env` file placed at the top-level directory. A reasonable example may use `[HOST] = '0.0.0.0'` and `[PORT] = 50262` to listen on all available IP addresses and an otherwise seldomly-used port.

To start a client, run
```
python run.py client --host=[HOST] --port=[PORT]
```
with `[HOST]` and `[PORT]` are the values of the server you wish to connect to. Similar to the server, you may also use the environment variables `$HOST` and `$PORT` instead of command-line arguments, for example through a `.env` file placed at the top-level directory.

Additional options can be viewed by running
```
python run.py --help
```
## Happy chatting!