# Password Manager
### Video Demo:  <https://youtu.be/C0YJXQHA5uU>
## Description:
The Password Manager is a command-line tool that allows users to store, manage, generate secure passwords and check strength of a password. It provides features such as adding new password entries, encrypting passwords for security, updating existing passwords, generating random passwords, and checking password strength.

## Design Choices
- **Read**: The `read()` function allows you to read and display the stored password entries from a password file. It prompts you to enter the filename or path of the password file to read. If the file exists, the function loads the entries from the file using the `load_from_file()` method. It then displays the entries in a tabular format using the `tabulate` library for better readability.

- **Write**: The `write()` function enables you to store new password entries. It prompts you to enter the filename for the password file, the website, username, and password for the new entry. If the file already exists, the function loads the existing entries from the file before adding the new entry. If the file does not exist, a new file is created with the provided filename. The entered password is encrypted before being stored in the file for enhanced security.

- **Update**: The `update()` function allows you to update an existing password entry in the password file. It prompts you to enter the filename or path of the password file to update. If the file exists, it loads the entries from the file and prompts you to enter the website and username of the entry you want to update. If a match is found, you can enter a new password, which will be encrypted and updated in the file. If no matching entry is found or the file does not exist, appropriate error messages are displayed.

- **Encryption**: The project uses the `cryptography` library for encrypting and decrypting passwords. This choice was made to ensure the security and confidentiality of the stored passwords. The `Fernet` encryption scheme with a pre-defined encryption key is used. The Fernet algorithm is a symmetric encryption algorithm based on the AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode. It provides secure encryption and decryption of data using a shared secret key which means that the same key is used for both encrypting and decrypting. The cryptography library handles the underlying cryptographic operations, ensuring the security of the encrypted passwords.

- **Password Strength Checking**: The `check_password_strength` function checks the strength of passwords based on various criteria, such as length, presence of uppercase and lowercase characters, digits, and special characters. This helps users assess the strength of their passwords and make necessary improvements.

- **File Storage**: Password entries are stored in a text file. Each entry is saved with the website, username, and encrypted password. The file can be loaded and updated with new entries or modified passwords.

- **User Interface**: The project provides a simple command-line interface with a menu-based system. Users can choose options by entering the corresponding numbers.


## Usage
To use the Password Manager, run the `project.py` file. You will be presented with a menu that allows you to perform various actions, such as reading passwords, storing passwords, updating passwords, generating passwords, and checking password strength. Simply follow the prompts and enter the required information as requested.
for the sake of simplicity the program uses sys.exit to exit if there are any errors or unexpected input instead of using while true to force desired input

Note: When entering passwords, they will be hidden for security purposes. Simply type the password and press Enter.

## Conclusion
The Password Manager is a handy tool for managing and securing passwords. It provides an easy-to-use interface for storing and updating passwords, generating strong passwords, and checking password strength. With its encryption capabilities, it ensures the confidentiality of stored passwords.

