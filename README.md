Secure Instant Messaging Application
1. Project Description:
The chat system that supports secure communication and is easy to use is the main purpose of this project developed in Python.
The server acts as an intermediate between two users and all conversations are protected by encryption.
The main idea is to demonstrate the application of AES, RSA, and digital signatures in actual communication.

2. Features:
RSA key pairs (public/private) are created for each user.
The public key goes to the server while the private key is kept with the user.
User A can talk to User B by first sending a secure AES session key to User B and vice versa.
AES is used to encrypt the messages.
In addition, each message is signed with RSA, and the receiver can verify the authenticity of the message.
The terminal gives a clear indication of:
verified signatures
invalid  signatures
encrypted messages
online users

3. How to run the project:
    1. Open Terminal:
        Start the server: python server.py
        The server will start and wait for clients to connect.
    2. Open New Terminal:
        Start a client: python client.py
        Enter a username when asked.
        Repeat this in another terminal window for the second user.
        Now you can choose who to talk to and send secure messages.

4. Project files:
    client.py: Runs the chat client
    server.py: Handles all messages and key requests
    rsa_utils.py: RSA key generation, encryption, and signatures
    crypto_utils.py: AES encryption and decryption
    screenshots/: Screenshots folder
    README.md: This file

