COMPANY: CODTECH IT SOLUTIONS

NAME: DONTHA SUSHRUTHA

INTERN ID:CTO4DF574

DOMAIN: CYBER SECURITY & ETHICAL HACKING

DURATION: 4 WEEKS

MENTOR:NEELA SANTOSH
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

### OUTPUT
![Image](https://github.com/user-attachments/assets/65e0c32b-bef8-4039-93ed-aacce9038818)

![Image](https://github.com/user-attachments/assets/f5b1f51c-1343-4c9b-bc25-2505ad99c4a3)

![Image](https://github.com/user-attachments/assets/91507e55-b091-40e3-b0f7-1ffc9c7002b2)
