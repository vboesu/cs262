# Distributed Chat Application Project Documentation

## Overview
This project implements a simple distributed chat application for our Distributed Computing course. The system comprises a multithreaded TCP server and a Tkinter-based client. Communication uses a custom binary wire protocol that is efficient, flexible, and easy to extend.

## Architecture
- **Server:**  
  A multithreaded TCP server that handles account management, message delivery, and read requests. It processes messages using our custom wire protocol and supports push notifications (e.g., new incoming messages). Note here in our interface we also added the JSON implementation, so that one can choose to use either our custome BCV protocol or the JSON version.
  
- **Client:**  
  A minimalistic GUI client built with Tkinter. The client sends requests to the server (e.g., create account, login, send message, read messages) and uses a dedicated listener thread to handle asynchronous responses and push notifications. Note here we also thought of the problem of the server pushing something to the client without the client prompting a request; so we actually handle this with two threads, one to process the message the client requested, and one to process spontaneous server pushes. 

## Wire Protocol Design

### Header (Fixed 8 Bytes)
- **Version (1 byte):**  
  Set to 1. This allows for future protocol upgrades.
- **Request Code (1 byte):**  
  Identifies the operation (e.g., create account, login, send message).
- **Flags/Status (2 bytes):**  
  Reserved for future use (set to 0).
- **Checksum (2 bytes):**  
  Computed as the sum of payload bytes modulo 65536. Provides basic error detection.
- **Payload Length (2 bytes):**  
  Indicates the length (in bytes) of the TLV-encoded payload.

### TLV-Encoded Payload
Each field in the payload is encoded as:
- **Field ID (1 byte)**
- **Field Length (2 bytes, little-endian)**
- **Field Value (raw bytes)**

**Common Field IDs:**
- `FIELD_USERNAME (1)`
- `FIELD_PASSWORD_HASH (2)`
- `FIELD_MESSAGE_CONTENT (3)`
- `FIELD_SENDER (4)`
- `FIELD_RECIPIENT (5)`
- `FIELD_TIMESTAMP (6)`
- `FIELD_MESSAGE_ID (7)` – (computed as the SHA‑256 of a composite message)
- `FIELD_UNREAD_COUNT (8)`
- `FIELD_PAGE_SIZE (11)`
- `FIELD_REQUEST_ID (13)` – Unique identifier for matching responses

## Server Operations
The server supports the following operations:

1. **Create Account (REQ_CREATE_ACCOUNT)**
   - **Input:** `FIELD_USERNAME`, `FIELD_PASSWORD_HASH`
   - **Output:** A confirmation message.

2. **Login (REQ_LOGIN)**
   - **Input:** `FIELD_USERNAME`, `FIELD_PASSWORD_HASH`
   - **Output:** Unread message count (`FIELD_UNREAD_COUNT`) and a confirmation message.
   - *Note:* (A session token could be added as an extension for security.)

3. **Send Message (REQ_SEND_MESSAGE)**
   - **Input:** `FIELD_SENDER`, `FIELD_RECIPIENT`, `FIELD_MESSAGE_CONTENT`
   - **Output:** A confirmation message and a message ID (`FIELD_MESSAGE_ID`).
   - **Mechanism:**  
     The server creates a composite TLV (including sender, content, timestamp), computes its SHA‑256 hash as the message ID, and either pushes the message to an online recipient or stores it as unread.

4. **Read Messages (REQ_READ_MESSAGES)**
   - **Input:** `FIELD_PAGE_SIZE` (number of messages to read)
   - **Output:** Unread messages concatenated with "||" as a separator.
   - **Mechanism:**  
     After returning messages, the server marks them as read.

### Asynchronous Response Handling
- **Unique Request ID:**  
  Every client request includes a unique Request ID (`FIELD_REQUEST_ID`), generated using UUID4.
- **Response Matching:**  
  The client maintains a thread-safe dictionary that maps Request ID (as hex strings) to a queue. When a request is sent, the client waits on its queue for a matching response.
- **Listener Thread:**  
  A dedicated background thread on the client continuously reads from the socket. When a response arrives:
  - If it includes a Request ID, it is placed in the corresponding queue.
  - Otherwise, it is handled as a push notification.
- **Benefit:**  
  This design avoids race conditions where the listener thread might consume a response intended for a synchronous request.

## Running Instructions

### Server
1. **Modify Server Binding (if necessary):**  
   To allow connections from other devices, bind the server to all interfaces:
   ```python
   server_sock.bind(("0.0.0.0", 9000))
