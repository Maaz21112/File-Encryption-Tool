import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from crypto_core import FileCrypto

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Crypto Tool")
        
        # Input File
        ttk.Label(root, text="Input File:").grid(row=0, column=0, padx=5, pady=5)
        self.input_entry = ttk.Entry(root, width=40)
        self.input_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(root, text="Browse", command=self.browse_input).grid(row=0, column=2)
        
        # Output File
        ttk.Label(root, text="Output File:").grid(row=1, column=0, padx=5, pady=5)
        self.output_entry = ttk.Entry(root, width=40)
        self.output_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(root, text="Browse", command=self.browse_output).grid(row=1, column=2)
        
        # Algorithm Selection
        ttk.Label(root, text="Algorithm:").grid(row=2, column=0, padx=5, pady=5)
        self.algorithm = ttk.Combobox(root, values=['AES', 'DES', 'DES3'])
        self.algorithm.grid(row=2, column=1, padx=5, pady=5)
        self.algorithm.current(0)
        
        # Password
        ttk.Label(root, text="Password:").grid(row=3, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(root, show="*", width=40)
        self.password_entry.grid(row=3, column=1, padx=5, pady=5)
        
        # Buttons
        ttk.Button(root, text="Encrypt", command=self.encrypt).grid(row=4, column=0, padx=5, pady=5)
        ttk.Button(root, text="Decrypt", command=self.decrypt).grid(row=4, column=1, padx=5, pady=5)
        
    def browse_input(self):
        filename = filedialog.askopenfilename()
        self.input_entry.delete(0, tk.END)
        self.input_entry.insert(0, filename)
        
    def browse_output(self):
        filename = filedialog.asksaveasfilename()
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, filename)
        
    def validate_fields(self):
        if not self.input_entry.get() or not self.output_entry.get():
            messagebox.showerror("Error", "Please select input and output files")
            return False
        if not self.password_entry.get():
            messagebox.showerror("Error", "Password cannot be empty")
            return False
        return True
        
    def encrypt(self):
        if self.validate_fields():
            try:
                crypto = FileCrypto(
                    self.password_entry.get(),
                    self.algorithm.get()
                )
                crypto.encrypt_file(
                    self.input_entry.get(),
                    self.output_entry.get()
                )
                messagebox.showinfo("Success", "File encrypted successfully!")
            except Exception as e:
                messagebox.showerror("Error", str(e))
                
    def decrypt(self):
        if self.validate_fields():
            try:
                crypto = FileCrypto(
                    self.password_entry.get(),
                    self.algorithm.get()
                )
                crypto.decrypt_file(
                    self.input_entry.get(),
                    self.output_entry.get()
                )
                messagebox.showinfo("Success", "File decrypted successfully!")
            except Exception as e:
                messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()