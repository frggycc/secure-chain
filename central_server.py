import socket
import threading

# List/Number of max connections
MAX_CONNECTIONS = 10;

HOST = '127.0.0.1'
PORT = 8470

# Might write to serperate file and use import
def handle_client(client_socket, client_address):
    while True:
        try:
            # Receive password and username from client
            log_data = client_socket.recv(1024).decode()
            if not log_data:
                break

            # Split where char = ':'
            username, password = log_data.split(":")

            # Test back with echo
            client_socket.send("Successful login".encode())

        except Exception as e:
            print(f"Error handling client: {e}")
            break

    client_socket.close()

# Runs only if thread == main one; 
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
