# Assignment
### Design exercise 1: Wire protocols

For this design exercise, you will be building a simple, client-server chat application. The application will allow users to send and receive text messages. There will be a centralized server that will mediate the passing of messages. The application should allow:

1. Creating an account. The user supplies a unique (login) name. If there is already an account with that name, the user is prompted for the password. If the name is not being used, the user is prompted to supply a password. The password should not be passed as plaintext.

2. Log in to an account. Using a login name and password, log into an account. An incorrect login or bad user name should display an error. A successful login should display the number of unread messages.

3. List accounts, or a subset of accounts that fit a text wildcard pattern. If there are more accounts than can comfortably be displayed, allow iterating through the accounts.

4. Send a message to a recipient. If the recipient is logged in, deliver immediately; if not the message should be stored until the recipient logs in and requests to see the message.

5. Read messages. If there are undelivered messages, display those messages. The user should be able to specify the number of messages they want delivered at any single time.

6. Delete a message or set of messages. Once deleted messages are gone.

7. Delete an account. You will need to specify the semantics of deleting an account that contains unread messages.

The client should offer a reasonable graphical interface. Connection information may be specified as either a command-line option or in a configuration file.

You will need to design the wire protocol – what information is sent over the wire. Communication should be done using sockets constructed between the client and server. It should be possible to have multiple clients connected at any time. Design your implementation using some care; there will be other assignments that will utilize this codebase.

You should build two implementations – one should use a custom wire protocol; you should strive to make this protocol as efficient as possible. The other should use JSON. You should then measure the size of the information passed between the client and the server, writing up a comparison in your engineering notebook, along with some remarks on what the difference makes to the efficiency and scalability of the service.

Implementations will be demonstrated to other members of the class on 2/10, where you will also undergo a code review of your code and give a code review of someone else. The code review should include evaluations of the test code coverage and documentation of the system. Code reviews, including a grade, will be turned in on Canvas, along with your engineering notebook and a link to your code repo.