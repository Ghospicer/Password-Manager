import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
import os
import hashlib
import base64

AUTO_LOCK_TIME = 300000  # 5 minutes cd

# Generate a key from a master key
def generate_key(master_key):
    key = hashlib.pbkdf2_hmac(
        'sha256',
        master_key.encode(),
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
def add_password(service, password, master_key, key_file='key.key', data_file='passwords.txt'):
    if not os.path.exists(key_file):
        key = generate_key(master_key)
        fernet = Fernet(key)
        save_key(key, key_file)
    else:
        key = load_key(key_file)
        fernet = key

    encrypted_password = encrypt_password(fernet, password)
    
    with open(data_file, 'a') as file:
        file.write(f"{service}:{encrypted_password.decode()}\n")

# Retrieve a password
def retrieve_password(service, master_key, key_file='key.key', data_file='passwords.txt'):
    if not os.path.exists(key_file):
        return "No key found. Cannot decrypt passwords."

    key = generate_key(master_key)
    fernet = Fernet(key)

    with open(data_file, 'r') as file:
        for line in file:
            stored_service, encrypted_password = line.strip().split(':')
            if stored_service == service:
                decrypted_password = decrypt_password(fernet, encrypted_password.encode())
                return decrypted_password
    return "No password found for this service."

# Delete a password
def delete_password(service, master_key, key_file='key.key', data_file='passwords.txt'):
    if not os.path.exists(key_file):
        return "No key found. Cannot delete passwords."

    key = generate_key(master_key)
    fernet = Fernet(key)

    with open(data_file, 'r') as file:
        lines = file.readlines()

    with open(data_file, 'w') as file:
        found = False
        for line in lines:
            stored_service, _ = line.strip().split(':')
            if stored_service != service:
                file.write(line)
            else:
                found = True
        if found:
            return f"Password for {service} deleted."
        else:
            return "No password found for this service."

# GUI
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.master_key = None

        self.key_file = 'key.key'
        self.data_file = 'passwords.txt'

        self.auto_lock_timer = None

        self.create_widgets()
        self.start_auto_lock_timer()

    def create_widgets(self):
        self.main_frame = tk.Frame(self.root, padx=20, pady=20, bg='#f0f0f0')
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Master Key Section
        tk.Label(self.main_frame, text="Master Password:", font=("Arial", 14), bg='#f0f0f0').grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        self.master_key_entry = tk.Entry(self.main_frame, show='*', font=("Arial", 14), width=40)
        self.master_key_entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)

        self.set_password_button = tk.Button(self.main_frame, text="Set Master Password", command=self.set_master_key, font=("Arial", 12), bg='#4CAF50', fg='white')
        self.set_password_button.grid(row=0, column=2, padx=10, pady=10)

        # Menu buttons
        self.menu_frame = tk.Frame(self.main_frame, padx=10, pady=10, bg='#f0f0f0')
        self.menu_frame.grid(row=1, column=0, columnspan=3, pady=10)

        self.add_password_button = tk.Button(self.menu_frame, text="Add Password", command=self.show_add_password_panel, font=("Arial", 12), bg='#2196F3', fg='white')
        self.add_password_button.pack(side=tk.LEFT, padx=10)

        self.retrieve_password_button = tk.Button(self.menu_frame, text="Retrieve Password", command=self.show_retrieve_password_panel, font=("Arial", 12), bg='#FFC107', fg='white')
        self.retrieve_password_button.pack(side=tk.LEFT, padx=10)

        self.delete_password_button = tk.Button(self.menu_frame, text="Delete Password", command=self.show_delete_password_panel, font=("Arial", 12), bg='#F44336', fg='white')
        self.delete_password_button.pack(side=tk.LEFT, padx=10)

        self.logout_button = tk.Button(self.menu_frame, text="Logout", command=self.logout, font=("Arial", 12), bg='#9E9E9E', fg='white')
        self.logout_button.pack(side=tk.LEFT, padx=10)

        # Toplevel panels for adding, retrieving, and deleting passwords
        self.add_password_panel = self.create_password_panel("Add Password", self.add_password)
        self.retrieve_password_panel = self.create_password_panel("Retrieve Password", self.retrieve_password)
        self.delete_password_panel = self.create_password_panel("Delete Password", self.delete_password)

    def create_password_panel(self, title, command):
        panel = tk.Toplevel(self.root)
        panel.title(title)
        panel.geometry("350x250")
        panel.withdraw()  # Start hidden

        tk.Label(panel, text="Service Name:", font=("Arial", 12)).pack(pady=5)
        service_name_entry = tk.Entry(panel, font=("Arial", 12))
        service_name_entry.pack(pady=5, padx=10, fill=tk.X)

        if title == "Add Password":
            tk.Label(panel, text="Password:", font=("Arial", 12)).pack(pady=5)
            password_entry = tk.Entry(panel, show='*', font=("Arial", 12))
            password_entry.pack(pady=5, padx=10, fill=tk.X)
        else:
            password_entry = None

        save_button = tk.Button(panel, text=title, command=lambda: command(service_name_entry, password_entry), font=("Arial", 12), bg='#4CAF50', fg='white')
        save_button.pack(pady=10)

        return panel

    def set_master_key(self):
        self.master_key = self.master_key_entry.get()
        if self.master_key:
            messagebox.showinfo("Password Manager", "Master password set.")
        else:
            messagebox.showwarning("Password Manager", "Please enter a master password.")
        self.reset_auto_lock_timer()

    def show_add_password_panel(self):
        if not self.master_key:
            messagebox.showwarning("Password Manager", "Master password not set.")
            return

        self.add_password_panel.deiconify()

    def show_retrieve_password_panel(self):
        if not self.master_key:
            messagebox.showwarning("Password Manager", "Master password not set.")
            return

        self.retrieve_password_panel.deiconify()

    def show_delete_password_panel(self):
        if not self.master_key:
            messagebox.showwarning("Password Manager", "Master password not set.")
            return

        self.delete_password_panel.deiconify()

    def add_password(self, service_name_entry, password_entry):
        service = service_name_entry.get()
        password = password_entry.get()

        if service and password:
            add_password(service, password, self.master_key, self.key_file, self.data_file)
            messagebox.showinfo("Password Manager", "Password added successfully.")
            self.add_password_panel.withdraw()
        else:
            messagebox.showwarning("Password Manager", "Service name or password cannot be empty.")

    def retrieve_password(self, service_name_entry, _):
        service = service_name_entry.get()

        if service:
            result = retrieve_password(service, self.master_key, self.key_file, self.data_file)
            messagebox.showinfo("Password Manager", f"Result: {result}")
            self.retrieve_password_panel.withdraw()
        else:
            messagebox.showwarning("Password Manager", "Service name cannot be empty.")

    def delete_password(self, service_name_entry, _):
        service = service_name_entry.get()

        if service:
            result = delete_password(service, self.master_key, self.key_file, self.data_file)
            messagebox.showinfo("Password Manager", f"Result: {result}")
            self.delete_password_panel.withdraw()
        else:
            messagebox.showwarning("Password Manager", "Service name cannot be empty.")

    def logout(self):
        self.master_key = None
        self.master_key_entry.delete(0, tk.END)
        messagebox.showinfo("Password Manager", "Logged out.")

    def start_auto_lock_timer(self):
        self.auto_lock_timer = self.root.after(AUTO_LOCK_TIME, self.auto_lock)

    def reset_auto_lock_timer(self):
        if self.auto_lock_timer:
            self.root.after_cancel(self.auto_lock_timer)
        self.start_auto_lock_timer()

    def auto_lock(self):
        self.logout()
        messagebox.showinfo("Password Manager", "App locked due to inactivity.")

# Main
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
