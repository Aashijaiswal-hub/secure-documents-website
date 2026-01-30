# SecureVault - Sovereign Identity & Document Storage
________________________________________
## 📖 About The Project

SecureVault isn't just a clone of Google Drive; it's a prototype for a **government-grade digital locker**. 

I built this platform to solve a specific problem: **Secure, verifiable document sharing for citizens.** Unlike standard cloud storage, SecureVault emphasizes identity verification (Aadhaar-based) and auditability. Every action—from login to file viewing—is logged in an immutable audit trail, making it suitable for sensitive legal or financial documents.

The core philosophy here is **"Privacy by Design."** Files aren't just saved; they are encrypted at rest using AES-256 before they ever touch the database.
________________________________________
## 🚀 Key Features

### 🔐 Security First
* **AES-256 Encryption:** Files are encrypted on upload. Even the database administrator cannot view user files without the decryption keys.
* **Production Hardening:** Implemented Rate Limiting, NoSQL Injection protection, and Parameter Pollution guards.
* **Identity Verification:** Mock Aadhaar-based registration system to ensure 1:1 identity mapping.

### 📂 Smart Organization
* **Virtual "Shared" System:** A unique approach to file sharing that doesn't duplicate data. Shared files appear in a dedicated, virtual "Shared with Me" directory.
* **Nested Folders:** Full support for deep folder structures with breadcrumb navigation.
* **Granular Permissions:** Time-limited sharing (e.g., "Grant access for 24 hours").

### ⚡ User Experience
* **Robust Error Handling:** Global Error Boundaries prevent "White Screen of Death" crashes.
* **Visual Feedback:** Professional skeleton loaders and toast notifications (no native browser alerts).
* **Responsive Dashboard:** Clean, grid-based UI that works on all devices.
________________________________________

## 🛠️ Tech Stack

* **Frontend:** React 18, Vite, Tailwind CSS, Radix UI.
* **Backend:** Node.js, Express 5.
* **Database:** MongoDB Atlas (GridFS for file chunking).
* **Security Tools:** Helmet, Express-Rate-Limit, Crypto (Node.js native), BCrypt.
________________________________________

## ⚙️ Local Setup Guide

Follow these steps to get the vault running locally.

### 1. Prerequisites
* Node.js (v18+)
* MongoDB URI (Local or Atlas)

### 2. Installation
Clone the repository: git clone https://github.com/DataWiseWizard/se-docx.git
Install Backend Dependencies: cd server npm install
Install Frontend Dependencies: cd ../client npm install
________________________________________
## 🛡️ Architecture Highlights
### The Encryption Pipeline
I chose not to rely on disk encryption alone. Instead, files undergo stream-based encryption:

Upload: File stream enters the server -> Enciphered using crypto module -> Chunks stored in GridFS.

Download: Chunks retrieved -> Deciphered on-the-fly -> Streamed to client. This ensures that at no point does the unencrypted file exist on the server's disk.

#### The Virtual Folder Logic
To avoid database clutter, the "Shared with Me" folder doesn't actually exist in the Folder collection. It is injected by the frontend and queries the acl (Access Control List) array on documents directly. This keeps the DB schema clean and the read operations fast.

## 🔮 Future Improvements
If I were to take this to a government scale, I would add:

Real Aadhaar API Integration: Replacing the mock verification with actual UIDAI hooks.

S3 Storage: Migrating from GridFS to AWS S3 for petabyte-scale storage capabilities.

2FA: Adding OTP-based Two-Factor Authentication for logins.s.
________________________________________
## AUTHOR
Rudraksha Kumbhkar

