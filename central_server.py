import socket
import threading

# List/Number of max connections
MAX_CONNECTIONS = 10;

# Might write to serperate file and use import
def handle_client(client_socket, client_address):
    print("Inside handle_client")

# Runs only if thread == main one; 
if __name__ == "__main__":
    host = '127.0.0.1'
    port = 8470

    # Create socket and bind (IPv4 and TCP)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(host, port)

    server_socket.listen(MAX_CONNECTIONS)

    # Create list of clients that will connect
    clients = []

    # Display status
    print(f"Server listening on {host}:{port}")

    # Eventually add authentication here!!!
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connected to {client_address}")
        clients.append(client_socket)

        # Create thread for each client connection
        # Might need to implement a way to avoid collisions
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()