# Secure Chat Application  
A Java-based secure messaging platform with authentication, encrypted communication, and audit logging to ensure confidentiality, integrity, and authenticity.  

---

## 📖 Overview  
This project implements a **centralized client-server chat application** designed to provide **tamper-proof and private communication**. It integrates **asymmetric cryptography (RSA, Diffie-Hellman)** and **symmetric AES encryption** to ensure end-to-end security, along with protection against replay attacks and unauthorized access.  

---

## ✨ Key Features  
- **User Authentication with Salted Hashes** – SHA-256(password + username)  
- **Automatic Public/Private Key Generation** for every user  
- **AES-CBC Message Encryption** with per-message random IVs  
- **Server-Facilitated RSA/DH Key Exchange** for session keys  
- **Mutual Challenge-Response Authentication** between client and server  
- **Perfect Forward Secrecy** with key rotation every 50 messages  
- **Replay Attack Protection** using timestamps, sequential processing, and unique IDs  
- **Audit Logging** to ensure traceability and reliability  

---

## 🔐 Security Protocol  
1. **Initial Connection** – RSA key pair generation and server public key exchange  
2. **User Authentication & Registration** – Secure salted hash validation  
3. **Mutual Authentication** – RSA-signed challenge-response mechanism  
4. **Diffie-Hellman Key Exchange** – Secure AES-128 session key derivation  
5. **Message Transmission** – AES-CBC encryption with IV per message  
6. **Perfect Forward Secrecy** – Session keys auto-rotated after 50 messages  
7. **Replay Attack Protection** – Timestamps, message ordering, and unique IDs  

---

## 📂 Project Structure  
```
/src   – Java source files for client and server
/logs  – Server audit logs
```

---

## 🚀 Getting Started  

### Prerequisites  
- Java 11 or higher  
- Eclipse IDE for Java Developers  

### Installation  
```bash
git clone https://github.com/Nadun-Dissanayake/Inforamtion-Security.git
```  
1. Open **Eclipse IDE**.  
2. Go to **File > Import > Existing Projects into Workspace**.  
3. Select the cloned folder and finish the import.  

### Running the Application  
- **Start the Server:** Locate the `Server` main class → *Right click > Run As > Java Application*  
- **Start a Client:** Locate the `Client` main class → *Right click > Run As > Java Application*  

---

## 📄 License  
This project is for **academic and research purposes**. Use responsibly.  
