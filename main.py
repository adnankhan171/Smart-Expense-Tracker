from database import db_handler
import getpass # for securely getting password input

def register():
    print('\n--- Register ---')
    username = input("Enter new username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return
    
    # Basic input validation for password length

    password = getpass.getpass("Enter new password")
    if len(password) < 6:
        print("password length must be at least 6 char long")
        return 
    confirm_password = getpass.getpass("Confirm password: ")

    if password != confirm_password:
        print("Passwords do not match. Please try again.")
        return

    if db_handler.add_user(username, password):
        print("Registration successful!")
    else:
        print("Registration failed")

def login():
    print("\n--- Login ---")
    username = input("Enter Username: ").strip()
    password = getpass.getpass("Enter Password: ")

    hashed_password_from_db = db_handler.get_user(username)

    if hashed_password_from_db:
        if db_handler.verify_password(password, hashed_password_from_db):
            print(f"Login successful! Welcome, {username}!")
            # Here you would typically start the main application logic for the logged-in user
            return True
        else:
            print("Invalid Password")
    else: 
        print("Username not found")
    return False

def main():
    db_handler.create_table()
    while True:
        print("\n--- CLI User System ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            register()
        elif choice == "2":
            if login():
                pass
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
