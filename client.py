from login import log_in, create_account
from encryption import encrypt_message, decrypt_message
import socket
import bcrypt
import ssl
import sys

# Get IP, port, and key from client
SERVER_IP = str(sys.argv[1])
SERVER_PORT = int(sys.argv[2])
SERVER_KEY = str(sys.argv[3])

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

# Verify if match with hash and message
def bcrypt_verify(message, hash):
    return bcrypt.checkpw(message.encode(), hash.encode())

def client_start():
    # Load CA certificate and client certificate
    # Fails if client ctr not signed by CA
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile="ca.crt")
    context.load_cert_chain(certfile="client.crt", keyfile="client.key")
    
    # Set socket settings
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Verify client before connecting them to the host
    with context.wrap_socket(client_socket, server_hostname="127.0.0.1") as secure_socket:
        secure_socket.connect((SERVER_IP, SERVER_PORT))

        # LOOP ONLY IF NEW ACCOUNT CREATED OR INVALID CHOICE
        choice = "0"
        while choice != "2":
            # Print options to client
            print("Welcome to Secure Chain")
            print(" 1. Create Account")
            print(" 2. Login into existing")
            choice = input(" Enter your choice (1 or 2): ")

            if choice == "1" or choice == "2":
                # Hash and send data
                data = bcrypt_append(choice)
                secure_socket.send(data.encode())

                # Receive data/status
                status = secure_socket.recv(1024).decode()
                print()
                print(status)

                # user's username and password to be validated
                username = input("Username: ")
                password = input("Password: ")
                login_info = encrypt_message(SERVER_KEY, f"{username}:{password}")
                secure_socket.send(login_info)
            
                # Was the sign-in valid?
                sign_valid = secure_socket.recv(1024).decode()
                print(sign_valid)
            #If no valid choice picked
            else:
                secure_socket.send(choice.encode())
                status = secure_socket.recv(1024).decode()
                
                print(status)

        # CLEAR AND GO TO DIFFERENT MENU TO SEND IN ORDERS

        secure_socket.close()
        
if __name__ == "__main__":
    client_start()
