import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes  # ✅ Correct hash import
import base64
import os
import secrets

# === Helper Functions ===

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from password using PBKDF2 with SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # ✅ FIXED
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(filepath: str, password: str) -> str:
    """
    Encrypt the file using AES-256-CFB mode.
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(16)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    if not os.path.exists("encrypted_files"):
        os.makedirs("encrypted_files")

    out_path = os.path.join("encrypted_files", os.path.basename(filepath) + ".enc")
    with open(out_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)

    return out_path

def decrypt_file(filepath: str, password: str) -> str:
    """
    Decrypt the file using AES-256-CFB mode.
    """
    with open(filepath, 'rb') as f:
        raw = f.read()

    salt = raw[:16]
    iv = raw[16:32]
    encrypted_data = raw[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    out_path = filepath.replace(".enc", ".dec")
    with open(out_path, 'wb') as f:
        f.write(decrypted_data)

    return out_path

# === GUI Logic ===

def browse_file():
    path = filedialog.askopenfilename()
    entry_file.delete(0, tk.END)
    entry_file.insert(0, path)

def encrypt_gui():
    filepath = entry_file.get()
    password = entry_pass.get()
    if not filepath or not password:
        messagebox.showerror("Error", "File path and password are required.")
        return

    try:
        out_path = encrypt_file(filepath, password)
        messagebox.showinfo("Success", f"Encrypted successfully:\n{out_path}")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def decrypt_gui():
    filepath = entry_file.get()
    password = entry_pass.get()
    if not filepath or not password:
        messagebox.showerror("Error", "File path and password are required.")
        return

    try:
        out_path = decrypt_file(filepath, password)
        messagebox.showinfo("Success", f"Decrypted successfully:\n{out_path}")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

# === GUI Setup ===

app = tk.Tk()
app.title("AES-256 File Encryption Tool")
app.geometry("500x230")
app.resizable(False, False)

tk.Label(app, text="Select File:").pack(pady=5)
entry_file = tk.Entry(app, width=50)
entry_file.pack()
tk.Button(app, text="Browse", command=browse_file).pack(pady=5)

tk.Label(app, text="Enter Password:").pack(pady=5)
entry_pass = tk.Entry(app, width=50, show="*")
entry_pass.pack()

tk.Button(app, text="Encrypt File", bg="lightgreen", command=encrypt_gui).pack(pady=10)
tk.Button(app, text="Decrypt File", bg="lightblue", command=decrypt_gui).pack(pady=5)

app.mainloop()
