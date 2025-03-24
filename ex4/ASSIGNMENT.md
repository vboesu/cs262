# Assignment
### Design exercise 4: Replication

Take one of the implementations you created for either of the first two design exercises (the chat application) and re-design and re-implement it so that the system is both persistent (it can be stopped and re-started without losing messages that were sent during the time it was running) and 2-fault tolerant in the face of crash/failstop failures. In other words, replicate the back end of the implementation, and make the message store persistent.

The replication can be done in multiple processes on the same machine, but you need to show that the replication also works over multiple machines (at least two). That should be part of the demo. Do not share a persistent store; this would introduce a single point of failure.

As usual, you will demo the system on Demo Day III (March 26). Part of the assignment is figuring out how you will demo both the new features. As in the past, keep an engineering notebook that details the design and implementation decisions that you make while implementing the system. You will need to turn in your engineering notebook and a link to your implementation code. As always, test code and documentation are a must.

Extra Credit: Build your system so that it can add a new server into its set of replicas.