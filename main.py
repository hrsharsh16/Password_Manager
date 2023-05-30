import sys
import os
from cryptography.fernet import Fernet
import getpass
from tabulate import tabulate
import random
import string


ENCRYPTION_KEY = b'ze-PWQT1ToiVjHt2hQrt42frnyeb4SZFnRykwDuyH2k='

class PasswordManager:
    def __init__(self):
        self.entries = []
        self.key = ENCRYPTION_KEY

    def add_entry(self, website, username, password):
        encrypted_password = self.encrypt_password(password)  # Encrypt the password
        entry = {"website": website, "username": username, "password": encrypted_password}
        self.entries.append(entry)

    def encrypt_password(self, password):
        f = Fernet(self.key)
        encrypted = f.encrypt(password.encode())
        return encrypted.decode()

    def decrypt_password(self, encrypted_password):
        f = Fernet(self.key)
        decrypted = f.decrypt(encrypted_password.encode())
        return decrypted.decode()

    def save_to_file(self, filename):
        try:
            with open(filename, "w") as file:
                for entry in self.entries:
                    file.write(f"Website: {entry['website']}\n")
                    file.write(f"Username: {entry['username']}\n")
                    file.write(f"Password: {entry['password']}\n")
                    file.write("\n")

        except IOError as e:
            print(f"An error occurred while accessing the file: {e}")
            sys.exit(style(100))

    def load_from_file(self, filename):
        self.entries = []
        try:
            with open(filename, "r") as file:
                lines = file.readlines()
                entry = {}
                for line in lines:
                    line = line.strip()
                    if line.startswith("Website:"):
                        entry["website"] = line.split(":")[1].strip()
                    elif line.startswith("Username:"):
                        entry["username"] = line.split(":")[1].strip()
                    elif line.startswith("Password:"):
                        entry["password"] = line.split(":")[1].strip()
                    elif line == "":
                        self.entries.append(entry)
                        entry = {}
        except FileNotFoundError:
            print("The password file was not found.")
            sys.exit(style(100))



def main():
    print("\n" + "*"*50 + "\n")
    print("Welcome To Password Manager\n".center(50))
    print("*"*50)
    print("*** MENU ***".center(50))
    print("1. Read Passwords")
    print("2. Store Passwords")
    print("3. Update Passwords")
    print("4. Generate Password")
    print("5. Check Password strength")
    mode = input(" Enter:  ")

    match mode:
        case "1":
            print(style(50))
            read()

        case "2":
            print(style(50))
            write()

        case "3":
            print(style(50))
            update()

        case "4":
            print(style(50))
            length = input("What should be the length of the password?")
            print(generate_password(length))

        case "5":
            print(style(50))
            password = input("what is the password?")
            if check_password_strength(password):
                print("your Password is strong, it uses a mix of uppercase numbers and special charecters")
                sys.exit(style(50))
            else:
                sys.exit("Your Password is Weak you should use mixed case charecters,  increase length and use special charecters and numbers" + f"\n{style(100)}")

        case _:
            print("INVALID: Choose a number between 1, 2, 3, 4 or 5")
            sys.exit(style(100))


def read():
    #input file to be read
    manager = PasswordManager()
    F = input("Filename: ")
    manager.load_from_file(f"{F}.txt")
    print("\n" + "*"*50)

    # asks for website whose PW to be retrieved
    website = input("Enter the website: ")
    found_entries = []

    # if any entry is found than stores it i found entries else prints not found
    for entry in manager.entries:
        if entry["website"] == website:
            found_entries.append(entry)

    if found_entries:
        table_data = []
        print(f"Found {len(found_entries)} entries for website '{website}':")
        for entry in found_entries:
            username = entry["username"]
            password = manager.decrypt_password(entry["password"])
            table_data.append([username, password])
            headers = ["Username", "Password"]
            table = tabulate(table_data, headers, tablefmt="fancy_grid")
            print(table)
            # print("Username:", entry["username"])
            # print("Password:", manager.decrypt_password(entry["password"]))
            sys.exit("\n" + "*"*50)
    else:
        print(f"No entries found for website '{website}'.")
        sys.exit("\n" + "*"*50)

def write():
    manager = PasswordManager()

    # Prompt for the filename
    filename = input("Enter the filename for the password file: ")
    filename = f"{filename}.txt"

    # Check if the file already exists
    file_exists = os.path.isfile(filename)

    if file_exists:
        # Load entries from an existing file
        manager.load_from_file(filename)

    # Prompt for the new password entry
    website = input("Enter the website: ")
    username = input("Enter the username: ")
    password = getpass.getpass("Enter the password: ")

    if not website or not username or not password:
        sys.exit("Error: Website, username, or password cannot be empty." + f"{style(100)}")

    # Add the new entry to the manager
    manager.add_entry(website, username, password)

    # Save the entries to the file
    manager.save_to_file(filename)

    if file_exists:
        print(f"Password entry added to {filename}")
    else:
        print(f"New password file {filename} created with the entry")


def update():
    manager = PasswordManager()

    filename = input("Enter the filename or path for the password file to update: ")
    filename = f"{filename}.txt"

    if os.path.isfile(filename):
        manager.load_from_file(filename)
        update_website = input("Website to update: ")
        update_user = input("User to update for: ")
        for entry in manager.entries:
            if entry["website"] == update_website and entry["username"] == update_user:
                new_pass = getpass.getpass("Enter the new password: ")
                if not new_pass:
                    sys.exit("password cannot be empty" + f"{style(100)}")
                pass_encryp = manager.encrypt_password(new_pass)
                entry["password"] = pass_encryp
                manager.save_to_file(filename)
                sys.exit("## Update Success ## \n exiting now ..." + f"{style(100)}")
            else:
                sys.exit("no such website or user in file please check again" + f"{style(100)}")

    else:
        sys.exit("No such file found" + f"{style(100)}")

def style(n):
    return "\n" + "*"*n

def generate_password(n):
    try:
        length = int(n)
    except ValueError:
        sys.exit("invalid number")
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def check_password_strength(password):
    length_valid = len(password) >= 8
    uppercase_valid = any(char.isupper() for char in password)
    lowercase_valid = any(char.islower() for char in password)
    digit_valid = any(char.isdigit() for char in password)
    special_char_valid = any(char in string.punctuation for char in password)

    return length_valid and uppercase_valid and lowercase_valid and digit_valid and special_char_valid

if __name__ == "__main__":
    main()
