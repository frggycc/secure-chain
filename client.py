import socket

server_host = "127.0.0.1"
server_port = 8470

if __name__ == "__main__":
    # Boot up client and connect to a server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))

    username = input("Username: ")
    password = input("Password: ")

    client_socket.send((f"{username}:{password}").encode())
        
    # Was the sign-in valid?
    sign_valid = client_socket.recv(1024).decode()
    print(sign_valid)

client_socket.close()
