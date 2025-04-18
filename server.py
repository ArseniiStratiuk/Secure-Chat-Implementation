"""Server implementation for secure chat application.

This module provides the server-side functionality for a secure chat application
with RSA encryption, digital signatures, and message integrity verification.
"""
import socket
import threading
import json
import hashlib
import secrets
import rsa


class Server:
    """Server class for managing client connections and message routing."""

    def __init__(self, port: int) -> None:
        """Initialize the server with the specified port.
        
        Args:
            port: Port number to bind the server to
        """
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.client_keys = {}  # store client public keys
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.public_key = None
        self.private_key = None
        self.buffer_size = 4096  # increase buffer size for large messages

    def start(self):
        """Start the server and listen for incoming connections."""
        self.s.bind((self.host, self.port))
        self.s.listen(100)
        
        # generate keys for the server
        self.public_key, self.private_key = rsa.rsa_algo()
        print(f"Server started on {self.host}:{self.port}")

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect from {addr}")
            
            self.username_lookup[c] = username
            self.clients.append(c)

            # send server public key to the client
            self.send_data(c, self.public_key)
            
            # receive client's public key
            client_public_key = self.receive_data(c)
            self.client_keys[c] = tuple(client_public_key)
            
            # generate a symmetric key for this client
            symmetric_key = secrets.token_hex(16)  # 128-bit key
            
            # encrypt the symmetric key with the client's public key
            encrypted_key = rsa.encrypt(symmetric_key, self.client_keys[c])
            
            # sign the encrypted key with server's private key for authentication
            signature = rsa.sign(str(encrypted_key), self.private_key)

            # send the encrypted key and signature to the client
            key_package = {
                "key": encrypted_key,
                "signature": signature
            }
            self.send_data(c, key_package)

            # broadcast new user joined message
            self.broadcast(f'New person has joined: {username}')

            threading.Thread(target=self.handle_client, args=(c,)).start()

    def send_data(self, client, data):
        """Send JSON data to a client with proper chunking for large messages.
        
        Args:
            client: Client socket
            data: Data to send
        """
        json_data = json.dumps(data)
        # encode length as 8-byte integer
        length = len(json_data).to_bytes(8, byteorder='big')
        client.send(length)
        client.sendall(json_data.encode())

    def receive_data(self, client):
        """Receive JSON data from a client with proper chunking for large messages.
        
        Args:
            client: Client socket
            
        Returns:
            Decoded JSON data
        """
        # receive message length as 8-byte integer
        length_bytes = client.recv(8)
        length = int.from_bytes(length_bytes, byteorder='big')
        
        # receive the actual data in chunks
        chunks = []
        bytes_received = 0
        while bytes_received < length:
            chunk_size = min(self.buffer_size, length - bytes_received)
            chunk = client.recv(chunk_size)
            if not chunk:
                raise ConnectionError("Connection broken during data transfer")
            chunks.append(chunk)
            bytes_received += len(chunk)
        
        # combine chunks and decode JSON
        data = b''.join(chunks).decode()
        return json.loads(data)

    def broadcast(self, msg: str):
        """Broadcast a message to all connected clients.
        
        Args:
            msg: Message to broadcast
        """
        clients_to_remove = []
        
        for client in self.clients:
            try:
                # calculate message hash for integrity
                msg_hash = hashlib.sha256(msg.encode()).hexdigest()
                
                # sign the hash with server's private key
                signature = rsa.sign(msg_hash, self.private_key)
                
                # prepare message package
                message_package = {
                    "sender": "SERVER",
                    "content": msg,
                    "hash": msg_hash,
                    "signature": signature
                }
                
                self.send_data(client, message_package)
            except Exception as e:
                print(f"Error broadcasting to client: {e}")
                clients_to_remove.append(client)
        
        # remove disconnected clients
        for client in clients_to_remove:
            if client in self.clients:
                self.clients.remove(client)

    def handle_client(self, c: socket):
        """Handle communication with a connected client.
        
        Args:
            c: Client socket
        """
        try:
            while True:
                try:
                    # receive message data
                    message_package = self.receive_data(c)
                    
                    # verify the message integrity using the hash
                    received_hash = message_package.get("hash")
                    content = message_package.get("content")
                    calculated_hash = hashlib.sha256(content.encode()).hexdigest()
                    
                    if received_hash != calculated_hash:
                        print(f"Warning: Message integrity check failed from {self.username_lookup[c]}")
                        continue
                    
                    # forward the message to other clients
                    for client in self.clients:
                        if client != c:
                            try:
                                self.send_data(client, message_package)
                            except Exception as e:
                                print(f"Error forwarding message to client: {e}")
                                # client will be removed on next broadcast
                except ConnectionError:
                    break
        except Exception as e:
            print(f"Error handling client {self.username_lookup.get(c, 'Unknown')}: {e}")
        finally:
            # remove disconnected client
            if c in self.clients:
                self.clients.remove(c)
            if c in self.username_lookup:
                print(f"{self.username_lookup[c]} disconnected")
                self.broadcast(f"{self.username_lookup[c]} left the chat")
                del self.username_lookup[c]
            if c in self.client_keys:
                del self.client_keys[c]
            c.close()


if __name__ == "__main__":
    s = Server(9001)
    s.start()
