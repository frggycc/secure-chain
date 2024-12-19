from login import log_in 
from login import create_account
import socket
import threading

# List/Number of max connections
MAX_CONNECTIONS = 10;

HOST = '127.0.0.1'
PORT = 6226

# Get password and username variables from client
def get_login(log_data):
    username, password = log_data.split(":")
    return username, password

# Might write to serperate file and use import
def handle_client(client_socket, client_address):
    while True:
        try:
            # Does client have an account or want to create one?
            log_choice = client_socket.recv(1024).decode()

            # Logging into existing account
            if log_choice == "2":
                print("In choice 2...")
                client_socket.send("Logging in...".encode())

                # Receive password and username from client
                log_data = client_socket.recv(1024).decode()
                username, password = get_login(log_data)

                # Check if login valid and successful
                valid_login = log_in(username, password)
                if valid_login == True:
                    client_socket.send("Successful login".encode())
                else:
                    client_socket.send("Invalid password or username".encode())

            # Creating new account
            elif log_choice == "1":
                print("In choice 1...")
                client_socket.send("Creating account...".encode())

                # Receive password and username from client
                log_data = client_socket.recv(1024).decode()
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

    # Create socket and bind (IPv4 and TCP)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(MAX_CONNECTIONS)

    # Display status
    print(f"Server listening on {HOST}:{PORT}")

    # Eventually add authentication here
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connected to {client_address}")

        # Create thread for each client connection
        # Might need to implement a way to avoid collisions
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()
