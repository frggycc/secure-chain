import bcrypt

def get_info(username, info_type):
    # Get email associate with username
    with open('profiles.txt', 'r') as profiles:
        for line in profiles:
            user_info = line.strip().split()

            if user_info and user_info[0] == username:
                if info_type == "email":
                    return user_info[3]
                elif info_type == "first":
                    return user_info[1]
                elif info_type == "last":
                    return user_info[2]


######### Creates Account ##############
# Returns False if it failed to create #
# or true if it was successful         #
########################################
def create_account(username, password, first, last, email):
    # Check if user already exists
    with open('db.txt', 'r') as db:
        for line in db:
            pass_info = line.strip().split()

            # Returns false if username exists
            if pass_info and pass_info[0] == username:
                return False

    """ Username is valid """
    # Hash the password and save the new account in db file
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    with open('db.txt', 'a') as db:
        db.write(f"{username} {hashed_password.decode('utf-8')}\n")

    with open('profiles.txt', 'a') as profile:
        profile.write(f"{username} {first} {last} {email}\n")
        
    print("Account has been created successfully...")
    return True

######### Checks Login Info #############
# Returns False if it failed to verify  #
# user password and true if it succeeds #
#########################################
def log_in(username, password):
    # Check if the user exists; Then verify password
    with open('db.txt', 'r') as db:
        for line in db:
            pass_info = line.strip().split()

            if pass_info and pass_info[0] == username:
                hashed_password = pass_info[1]

                if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                    # print("Login successful...")
                    return True

                # Username found; Password mismatch
                else:
                    # print("Invalid password. Login denied.")
                    return False
    
    # When username not found in db
    # print("Username not found. Login denied.")
    return False
