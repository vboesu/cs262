# Bright-Vincent Chat with Replication Documentation

### Overview
The replication is implemented as a leader-follower replication. We define a configuration file with a list of possible replicas with is used both by the client and the server instances. A replica is defined by a unique integer ID, a host, a port for communication with clients, and an internal port for communication among replicas (of course, in a production environment, this port would not be visible to the client).

The client can send its request to any of the replicas. If it sends it to a follower, the follower forwards the request without processing it to the leader to ensure data consistency.

### Connections
All communication happens over sockets. We decided to not keep any connecting sockets open beyond the delivery of a message to allow for push notifications even in the event when the leader fails. This means that to return a response, the server has to initiate a connection with the client, which requires the client to serve as its own server on a pre-specified/randomly selected port which is returned as part of any request (also, the client needs to have a very permissive firewall).

### Heartbeats & Leader Elections
The leader sends periodic heartbeats to all possible replicas to alert them of its presence. If a replica has not received a heartbeat from a leader within three times the heartbeat interval, it calls an election and messages all peers with lower IDs than itself. If it does not receive a response, it assumes that it has the lowest ID and declares itself the leader to all other peers.

There are many problems with this election protocol (for example, what happens if a leader is only temporarily unavailable or overloaded) but under the assumption of only failstops or crashes, it should work fine.

### Start-up
We can start up any number of machines, as long as at the time of the start up of the first of them, all possible replicas are defined in the configuration file. Each machine starts as a follower, and if it hasn't heard from a leader, it will call an election.

### Adding machines
Every machine has an internal logical clock. When a machine is added to the system after the first requests have been processed, the replica receiving the request to be processed notices this (because the timestamp of the request is too far in the future), and requests to be brought up to date by the leader. The leader then sends all requests which the new replica hasn't seen yet (in a separate thread so as to not block its usual operation) to the new replica until it has been brought up to date.

### Run
To run a server instance, run
```
python run.py server -i [ID of instance]
```

To run a client, run
```
python run.py client
```

For more information on the arguments available, you can run
```
python run.py --help
```

### Happy Chatting!