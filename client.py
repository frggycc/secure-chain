import socket

server_host = "127.0.0.1"
server_port = 6226

if __name__ == "__main__":
    # Boot up client and connect to a server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))

    print("Welcome to Secure Chain")
    print(" 1. Create Account")
    print(" 2. Login into existing")
    choice = input(" Enter your choice (1 or 2): ")

    # If already exists
    if choice == "2":
        client_socket.send(choice.encode())
        status = client_socket.recv(1024).decode()
        print()
        print(status)

        # user's username and password to be validated
        username = input("Username: ")
        password = input("Password: ")
        client_socket.send((f"{username}:{password}").encode())
    
        # Was the sign-in valid?
        sign_valid = client_socket.recv(1024).decode()
        print(sign_valid)
    # If a new one needs to be created
    elif choice == "1":
        client_socket.send(choice.encode())
        status = client_socket.recv(1024).decode()
        print()
        print(status)

        # New username and password to be used
        username = input("Username: ")
        password = input("Password: ")
        client_socket.send((f"{username}:{password}").encode())

        # Was the creation valid?
        create_valid = client_socket.recv(1024).decode()
        print(create_valid)
    #If no valid choice picked
    else:
        client_socket.send(choice.encode())
        status = client_socket.recv(1024).decode()
        
        print(status)
    

client_socket.close()
