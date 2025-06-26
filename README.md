# Advanced encryption tool

##  Objective
Build a robust encryption application to encrypt and decrypt files using AES-256 encryption with a user-friendly interface.

##  Features
- AES-256 encryption (CFB mode) using `cryptography` module
- Password-based key derivation using PBKDF2 + SHA256
- Supports all file types: PDF, DOCX, TXT, ZIP, JPG, etc.
- GUI-based interface using `tkinter`
- Encrypted files saved as `.enc`
- Decrypted files saved as `.dec`
- Files stored in `encrypted_files/` folder
- Error handling for missing inputs or incorrect password
- Clean, commented, and easy-to-understand code

## Technology Stack
- Language: Python 3.13
- GUI: Tkinter
- Encryption: cryptography (AES-256)
- Hashing: PBKDF2HMAC + SHA256

##  How to Run the Project

### 1. Install Required Libraries
```bash
pip install cryptography
```
Or if using requirements file:
```bash
pip install -r requirements.txt
```

### 2. Run the Program
```bash
python main.py
```

## How to Use

###  Encrypt a File
1. Click "Browse" and select any file (PDF, DOCX, JPG, etc.)
2. Enter a password
3. Click "Encrypt File"
4. Encrypted output will be saved in `encrypted_files/` as `filename.ext.enc`

###  Decrypt a File
1. Browse and select the `.enc` file
2. Enter the same password used for encryption
3. Click "Decrypt File"
4. Decrypted output will be saved as `filename.ext.dec`

> You can manually rename `.dec` files back to the original extension if needed.

## Notes
- Password is required for both encryption and decryption.
- Use the same password to decrypt — there's no password recovery.
- Each encryption uses random salt and IV, enhancing security.
- Fully offline and secure — no data is sent anywhere.
