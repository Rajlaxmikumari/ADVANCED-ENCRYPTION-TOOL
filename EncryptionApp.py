import tkinter as tk
from tkinter import filedialog, messagebox
from crypto_engine import AESCipher

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 Encryption Tool")
        self.cipher = AESCipher()
        self.setup_ui()

    def setup_ui(self):
        # File selection
        tk.Label(self.root, text="File:").grid(row=0, column=0, padx=5, pady=5)
        self.file_entry = tk.Entry(self.root, width=50)
        self.file_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(self.root, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=5, pady=5)

        # Password
        tk.Label(self.root, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(self.root, show="*", width=50)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        # Action buttons
        tk.Button(self.root, text="Encrypt", command=self.encrypt, bg="green", fg="white").grid(row=2, column=0, padx=5, pady=5)
        tk.Button(self.root, text="Decrypt", command=self.decrypt, bg="blue", fg="white").grid(row=2, column=1, padx=5, pady=5)

        # Status
        self.status = tk.StringVar(value="Ready")
        tk.Label(self.root, textvariable=self.status, fg="gray").grid(row=3, column=0, columnspan=3, padx=5, pady=5)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)

    def encrypt(self):
        self.process_file(operation='encrypt')

    def decrypt(self):
        self.process_file(operation='decrypt')

    def process_file(self, operation):
        input_file = self.file_entry.get()
        password = self.password_entry.get()

        if not input_file:
            messagebox.showerror("Error", "Please select a file")
            return
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return

        try:
            if operation == 'encrypt':
                output_file = self.cipher.encrypt_file(input_file, password)
                message = f"File encrypted successfully: {output_file}"
            else:
                output_file = self.cipher.decrypt_file(input_file, password)
                message = f"File decrypted successfully: {output_file}"

            self.status.set(message)
            messagebox.showinfo("Success", message)
        except Exception as e:
            self.status.set(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Operation failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
