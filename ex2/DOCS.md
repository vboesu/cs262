# Bright-Vincent Chat Documentation

## Overview
This project implements a simple distributed chat application for our Distributed Computing course. The system comprises a TCP server and a `tkinter`-based client. Communication between client and server uses gRPC.

## Architecture
- **Server:**
  The server runs on a single thread and processes requests in the order they arrive. It supports simple user management (account creation, login, deletion, search) and messaging (sending, receiving).
  
- **Client:**  
  A minimalistic GUI client built with `tkinter`. The client sends requests to the server (e.g., create account, login, send message, read messages) and uses a dedicated listener thread to handle responses as a result from requests sent by the client and push notifications from the server, e.g. when receiving a message while online.

## Testing
We created unit tests for the code shared by the client and the server, in particular our custom wire protocol encoder and decoder, and the request library which takes care of creating, transmitting, receiving, and parsing requests. To run the tests, run
```
python -m pytest tests
```

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