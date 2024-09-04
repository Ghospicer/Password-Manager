from cryptography.fernet import Fernet
import os
import getpass
import hashlib
import base64

# Generate a key from a master key
def generate_key(master_password):
    key = hashlib.pbkdf2_hmac(
        'sha256',
        master_password.encode(),
        b'salt',
        100000
    )
    return base64.urlsafe_b64encode(key[:32])

# Save the key to a file
def save_key(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)

# Load the key from a file
def load_key(filename):
    with open(filename, 'rb') as file:
        key = file.read()
    return Fernet(key)

# Encrypt the password
def encrypt_password(fernet, password):
    return fernet.encrypt(password.encode())

# Decrypt the password
def decrypt_password(fernet, encrypted_password):
    return fernet.decrypt(encrypted_password).decode()

# Add a new password
def add_password(service, password, master_password, key_file='key.key', data_file='passwords.txt'):
    if not os.path.exists(key_file):
        key = generate_key(master_password)
        fernet = Fernet(key)
        save_key(key, key_file)
    else:
        key = load_key(key_file)
        fernet = key

    encrypted_password = encrypt_password(fernet, password)
    
    with open(data_file, 'a') as file:
        file.write(f"{service}:{encrypted_password.decode()}\n")

# Retrieve a password
def retrieve_password(service, master_password, key_file='key.key', data_file='passwords.txt'):
    if not os.path.exists(key_file):
        print("No key found. Cannot decrypt passwords.")
        return
    
    key = generate_key(master_password)
    fernet = Fernet(key)
    
    with open(data_file, 'r') as file:
        for line in file:
            stored_service, encrypted_password = line.strip().split(':')
            if stored_service == service:
                decrypted_password = decrypt_password(fernet, encrypted_password.encode())
                return decrypted_password
    return None

# Delete a password
def delete_password(service, master_password, key_file='key.key', data_file='passwords.txt'):
    if not os.path.exists(key_file):
        print("No key found. Cannot delete passwords.")
        return

    key = generate_key(master_password)
    fernet = Fernet(key)

    # Read all lines from the existing file
    with open(data_file, 'r') as file:
        lines = file.readlines()

    # Write all lines except the one to be deleted
    with open(data_file, 'w') as file:
        for line in lines:
            stored_service, _ = line.strip().split(':')
            if stored_service != service:
                file.write(line)
            else:
                print(f"Password for {service} deleted.")

# Main loop
def main():
    master_password = getpass.getpass("Enter your master password: ")

    while True:
        choice = input("\nChoose an option: [1] Add Password [2] Retrieve Password [3] Delete Password [4] Quit\n")
        if choice == '1':
            service = input("Enter the service name: ")
            password = getpass.getpass("Enter the password for this service: ")
            add_password(service, password, master_password)
            print(f"Password for {service} added.")
        elif choice == '2':
            service = input("Enter the service name: ")
            password = retrieve_password(service, master_password)
            if password:
                print(f"Password for {service}: {password}")
            else:
                print(f"No password found for {service}.")
        elif choice == '3':
            service = input("Enter the service name: ")
            delete_password(service, master_password)
        elif choice == '4':
            break
        else:
            print("Invalid option. Please choose 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()
