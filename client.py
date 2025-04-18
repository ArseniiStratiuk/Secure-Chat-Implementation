"""Client implementation for secure chat application.

This module provides the client-side functionality for a secure chat application
with RSA encryption, digital signatures, and message integrity verification.
"""
import socket
import threading
import json
import hashlib
import rsa


class Client:
    """Client class for connecting to the chat server."""

    def __init__(self, server_ip: str, port: int, username: str) -> None:
        """Initialize the client with server details and username."""
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.public_key = None
        self.private_key = None
        self.server_public_key = None
        self.symmetric_key = None
        self.s = None
        self.buffer_size = 4096  # increase buffer size for large messages
        self.connected = False

    def send_data(self, data):
        """Send JSON data to the server with proper chunking for large messages.
        
        Args:
            data: Data to send
        """
        json_data = json.dumps(data)
        # encode length as 8-byte integer
        length = len(json_data).to_bytes(8, byteorder='big')
        self.s.send(length)
        self.s.sendall(json_data.encode())

    def receive_data(self):
        """Receive JSON data from the server with proper chunking for large messages.
        
        Returns:
            Decoded JSON data
        """
        # receive message length as 8-byte integer
        length_bytes = self.s.recv(8)
        if not length_bytes:
            raise ConnectionError("Connection closed by server")

        length = int.from_bytes(length_bytes, byteorder='big')

        # receive the actual data in chunks
        chunks = []
        bytes_received = 0
        while bytes_received < length:
            chunk_size = min(self.buffer_size, length - bytes_received)
            chunk = self.s.recv(chunk_size)
            if not chunk:
                raise ConnectionError("Connection broken during data transfer")
            chunks.append(chunk)
            bytes_received += len(chunk)

        # combine chunks and decode JSON
        data = b''.join(chunks).decode()
        return json.loads(data)

    def init_connection(self):
        """Initialize the connection to the server."""
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        # create key pairs
        print("Generating RSA keys...")
        self.public_key, self.private_key = rsa.rsa_algo()
        print("Keys generated!")

        try:
            # receive server's public key
            print("Receiving server public key...")
            self.server_public_key = tuple(self.receive_data())
            print("Server public key received!")

            # send public key to the server
            print("Sending public key to server...")
            self.send_data(self.public_key)
            print("Public key sent!")

            # receive the encrypted symmetric key
            print("Receiving encrypted key...")
            key_package = self.receive_data()
            encrypted_key = key_package["key"]
            key_signature = key_package["signature"]
            print("Encrypted key received!")

            # verify the signature of the key
            if rsa.verify(str(encrypted_key), key_signature, self.server_public_key):
                # decrypt the symmetric key
                self.symmetric_key = rsa.decrypt(encrypted_key, self.private_key)
                print("Secure connection established!")
                self.connected = True
            else:
                print("WARNING: Server authentication failed!")
                return

            message_handler = threading.Thread(target=self.read_handler, args=())
            message_handler.start()
            input_handler = threading.Thread(target=self.write_handler, args=())
            input_handler.start()

        except Exception as e:
            print(f"Error during connection setup: {e}")
            return

    def read_handler(self):
        """Handle incoming messages from the server."""
        while self.connected:
            try:
                # receive and parse message
                message_package = self.receive_data()

                # verify message integrity using hash
                received_hash = message_package.get("hash")
                content = message_package.get("content")
                sender = message_package.get("sender", "Unknown")
                signature = message_package.get("signature")

                calculated_hash = hashlib.sha256(content.encode()).hexdigest()

                # check hash integrity
                if received_hash != calculated_hash:
                    print("Warning: Message integrity check failed!")
                    continue

                # verify signature (from server or pass through from another client)
                if sender == "SERVER" and not rsa.verify(received_hash,
                                                         signature,
                                                         self.server_public_key):
                    print("Warning: Server message signature verification failed!")
                    continue

                # display the message
                print(f"{sender if sender != 'SERVER' else '[SERVER]'}: {content}")

            except ConnectionError:
                print("Connection to server lost")
                self.connected = False
                break
            except Exception as e:
                print(f"Error receiving message: {e}")
                self.connected = False
                break

        print("Disconnected from server")

    def write_handler(self):
        """Handle outgoing messages to the server."""
        while self.connected:
            try:
                message = input()

                # calculate message hash for integrity
                msg_hash = hashlib.sha256(message.encode()).hexdigest()

                # sign the hash with our private key
                signature = rsa.sign(msg_hash, self.private_key)

                # prepare message package
                message_package = {
                    "sender": self.username,
                    "content": message,
                    "hash": msg_hash,
                    "signature": signature
                }

                self.send_data(message_package)

            except Exception as e:
                print(f"Error sending message: {e}")
                self.connected = False
                break


if __name__ == "__main__":
    username = input("Enter your username: ")
    cl = Client("127.0.0.1", 9001, username)
    cl.init_connection()
