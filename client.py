from login import log_in, create_account
from encryption import encrypt_message, decrypt_message
import socket
import bcrypt
import ssl
import sys
import os
import getpass

# Get IP, port, and key from client
SERVER_IP = str(sys.argv[1])
SERVER_PORT = int(sys.argv[2])
SERVER_KEY = str(sys.argv[3])
CLIENT_CRT = "client.crt"
CLIENT_KEY = "client.key"

# # Encrypt with AES; Accept decoded and return encoded
# def encrypt_message(key, message):

# # Decrypt messages; Accept encoded and returns decode plaintext
# def decrypt_message(key, enc_message):

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
    context.load_cert_chain(certfile=CLIENT_CRT, keyfile=CLIENT_KEY)
    
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
                # Append hash to data for verification
                data = bcrypt_append(choice)
                secure_socket.send(data.encode())

                # Receive data/status
                status = secure_socket.recv(1024).decode()
                print()
                print(status)

                # user's username and password to be validated
                username = input("Username: ")
                password = getpass.getpass("Password: ")

                # Ask for more info if creating account
                if choice == "1":
                    first = input("First Name: ")
                    last = input("Last Name: ")
                    email = input("Email: ")
                    message = f"{username}:{password}:{first}:{last}:{email}"
                else:
                    message = f"{username}:{password}"

                login_info = encrypt_message(SERVER_KEY, message)
                secure_socket.send(login_info)
            
                # Was the sign-in valid?
                sign_valid = secure_socket.recv(1024).decode()
                print(sign_valid)

                if sign_valid != "Successful login":
                    choice == "0"

            #If no valid choice picked
            else:
                secure_socket.send(choice.encode())
                status = secure_socket.recv(1024).decode()
                print(status)
       
        # LOOP FINISHED; USER VERIFIED
        # CLEAR AND GO TO DIFFERENT MENU TO SEND IN ORDERS
        ## _ = os.system('clear')
            # LOOP FINISHED; USER VERIFIED
        # CLEAR AND GO TO DIFFERENT MENU TO SEND IN ORDERS
        ## _ = os.system('clear')
    
        # Order system
        print("Welcome to the Airplane Parts Ordering System")
        print("Available parts:")
        print("1. Actuators - $500")
        print("2. Hydraulics - $800")
        print("3. Manifolds - $600")
        print("4. Valves - $300")
        print("5. Rods - $150")

        order = []
        while True:
            print("\nMenu:")
            print("1. Add an item to your order")
            print("2. View your current order")
            print("3. Complete your order and exit")
            choice = input("Enter your choice (1, 2, or 3): ")

            if choice == "1":
                part = input("Enter the part number (1-5): ")
                quantity = input("Enter the quantity: ")

                if part in ["1", "2", "3", "4", "5"] and quantity.isdigit():
                    part_name = {
                        "1": "Actuators",
                        "2": "Hydraulics",
                        "3": "Manifolds",
                        "4": "Valves",
                        "5": "Rods"
                    }[part]
                    order.append((part_name, int(quantity)))
                    print(f"Added {quantity} x {part_name} to your order.")
                else:
                    print("Invalid part number or quantity. Please try again.")
            elif choice == "2":
                if order:
                    print("\nYour current order:")
                    for item, qty in order:
                        print(f"{item}: {qty}")
                else:
                    print("Your order is empty.")
            elif choice == "3":
                if order:
                    order_message = "Order details:\n" + "\n".join(
                        f"{item}: {qty}" for item, qty in order
                    )
                    encrypted_order = encrypt_message(SERVER_KEY, order_message)
                    secure_socket.send(encrypted_order)
                    print("\nYour order has been placed. Thank you!")
                else:
                    print("You did not order anything. Exiting...")
                break
            else:
                print("Invalid choice. Please choose 1, 2, or 3.")

    secure_socket.close()


    secure_socket.close()
        
if __name__ == "__main__":
    client_start()
