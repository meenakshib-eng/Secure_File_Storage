# Project Title: Secure File Storage with Role-Based Access Control (RBAC)
 Overview
This project implements a **Secure File Storage System** that protects files using encryption and controls access using **Role-Based Access Control (RBAC)**. It ensures confidentiality, integrity, and controlled access to sensitive files.


The system combines:
- AES for data encryption  
- RSA/ECC for secure key wrapping  
- SHA-3 / HMAC for integrity  
- Database-based RBAC for user permission management  

 Objectives
1. Protect files using **AES symmetric encryption**.
2. Use **RSA/ECC** for key wrapping and distributing encryption keys securely.
3. Ensure file integrity using **SHA-3 or HMAC**.
4. Enforce **Role-Based Access Control (RBAC)** to manage read/write/decrypt permissions.
5. Provide a secure environment for uploading, storing, and retrieving encrypted files.

 Key Features
- **User Registration & Authentication**
- **RBAC with predefined roles** (admin, manager, user)
- **AES-256 encryption** for files
- **RSA/ECC public-key cryptography** for wrapping AES keys
- **SHA-3/HMAC hashing** to detect modification or tampering
- **Secure file upload/download**
- **Audit logs for security monitoring**
- **Modular code structure** for easy expansion

 System Architecture
- **langauge:** Python  
- **Database:** SQLite / MySQL  
- **Crypto Libraries:** `cryptography`, `PyCryptodome`

### **How It Works**

   AES Encryption

Each uploaded file is encrypted using AES-256 (CBC/GCM).
A random AES key is generated per file.

RSA/ECC Key Wrapping

The AES key is encrypted using the user’s public key.
Only the holder of the private key can unwrap and decrypt the file.

File Integrity (SHA-3 / HMAC)

A hash is generated before encryption.
The system verifies it during decryption.

 RBAC Permissions

Roles control which operations are allowed:


