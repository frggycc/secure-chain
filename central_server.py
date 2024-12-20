from login import log_in, create_account
from encryption import encrypt_message, decrypt_message
import socket
import bcrypt
import ssl
import threading

# List/Number of max connections
MAX_CONNECTIONS = 10;
HOST = '127.0.0.1'
PORT = 6226
KEY = "1234567890123456"

# # Encrypt with AES; Accept decoded and return encoded
# def encrypt_message(message):

# # Decrypt messages; Accept encoded and returns decode plaintext
# def decrypt_message(enc_message):

# Verify message integrity
def bcrypt_append(message):
    hashed_message, _ = bcrypt_hash(message)
    data = f"{message}:{hashed_message.decode()}"
    return data

# Generate a bcrypt hash of a message
def bcrypt_hash(message):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(message.encode(), salt)
    return hashed, salt

# Verify match with hash and message
def bcrypt_verify(message, hash):
    return bcrypt.checkpw(message.encode(), hash.encode())

# Get password and username variables from client
def get_login(log_data):
    username, password = log_data.split(":")
    return username, password

# Might write to serperate file and use import
def handle_client(client_socket, client_address):
    while True:
        try:
            # Receive data
            data = client_socket.recv(1024).decode()
            log_choice, received_hash = data.split(":")

            # Verify integrity; Exit if both don't match
            if not bcrypt_verify(log_choice, received_hash):
                print("Integrity check failed...")
                break
            
            # Logging into existing account
            if log_choice == "2":
                client_socket.send("Logging in...".encode())

                # Receive encrypted log in, then decrypt
                enc_data = client_socket.recv(1024)
                log_data = decrypt_message(KEY, enc_data)
                username, password = get_login(log_data)

                # Check if login valid and successful
                valid_login = log_in(username, password)
                if valid_login == True:
                    client_socket.send("Successful login".encode())
                    ### ACCEPT ORDERS HERE; DECRYPT AND VERIFY

                    client_socket.close()
                else:
                    client_socket.send("Invalid password or username".encode())

            # Creating new account
            elif log_choice == "1":
                client_socket.send("Creating account...".encode())

                # Receive encrypted log in, then decrypt
                enc_data = client_socket.recv(1024)
                log_data = decrypt_message(enc_data)
                username, password = get_login(log_data)

                # Check if creation successful or not
                valid_login = create_account(username, password)
                if valid_login == True:
                    client_socket.send("Account successfully created!".encode())
                else:
                    client_socket.send("Username already exists!".encode())
            
            # Invalid choice selection
            else:
                print("In invalid choice...")
                client_socket.send("Invalid choice".encode())

        except Exception as e:
            print(f"Error handling client: {e}")
            break
        
    client_socket.close()

if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')

    # Create socket and bind (IPv4 and TCP)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(MAX_CONNECTIONS)

    with context.wrap_socket(server_socket, server_side=True) as secure_socket:
    #    Eventually add authentication here
        # Display status
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            client_socket, client_address = secure_socket.accept()
            print(f"Connected to {client_address}")

            # Create thread for each client connection
            # Might need to implement a way to avoid collisions
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
