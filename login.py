import bcrypt

######### Creates Account ##############
# Returns False if it failed to create #
# or true if it was successful         #
########################################
def create_account(username, password):
    # Check if user already exists
    with open('db.txt', 'r') as db:
        for line in db:
            existing_username, _ = line.strip().split('', 1)

            # Returns to create account screen is username exists
            if existing_username == username:
                print("Username already exists. Please choose a different username.")
                return False

    """ Username is valid """
    # Hash the password and save the new account in db file
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    with open('db.txt', 'a') as db:
        db.write(f"{username} {hashed_password.decode('utf-8')}\n")
    
    print("Account has been created successfully...")
    return True

######### Checks Login Info #############
# Returns False if it failed to verify  #
# user password and true if it succeeds #
#########################################
def login(username, password):
    # Check if the ruser exists; Then verify password
    with open('db.txt', 'r') as db:
        for line in db:
            existing_username, hashed_password = line.strip().split('', 1)
            # Username found; Passwords match
            if existing_username == username:
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                    print("Login successful...")
                    return True

            # Username found; Password mismatch
            else:
                print("Invalid password. Login denied.")
                return False
    
    # When username not found in db
    print("Username not found. Login denied.")
    return False
