# Secure Chat System - Console-Based Implementation

A comprehensive secure chat application demonstrating cryptographic principles for achieving Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR) in a client-server architecture.

## Overview

This implementation provides a console-based secure messaging system that integrates multiple cryptographic primitives:

- **X.509 Certificate-Based Authentication**: Mutual certificate verification using a self-signed root CA
- **Diffie-Hellman Key Exchange**: Secure session key derivation without transmitting keys over the network
- **AES-128 Encryption**: Block cipher encryption for message confidentiality
- **RSA Digital Signatures**: Message integrity and authenticity verification
- **Session Transcripts**: Append-only logs with signed receipts for non-repudiation

## System Architecture

The system operates in four distinct phases:

1. **Control Plane (Negotiation and Authentication)**: Certificate exchange and mutual verification
2. **Key Agreement**: Diffie-Hellman key exchange for session key derivation
3. **Data Plane (Encrypted Communication)**: Secure message exchange with integrity protection
4. **Tear Down (Non-Repudiation)**: Session transcript and receipt generation

## Prerequisites

- Python 3.7 or higher
- MySQL or MariaDB database server
- Required Python packages (see Installation section)

## Installation

1. **Clone or download this repository**

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install required dependencies**:
   ```bash
   pip install cryptography pycryptodome pymysql
   ```

4. **Set up MySQL/MariaDB database**:
   - Create a database named `securechat` (or your preferred name)
   - Create a user with appropriate permissions
   - Note the connection credentials

5. **Configure database environment variables**:
   ```bash
   export DB_HOST=localhost
   export DB_USER=chatuser
   export DB_PASS='YourSecurePassword'
   export DB_NAME=securechat
   ```

## Certificate Authority Setup

Before running the server or client, you must generate a root CA and issue certificates:

1. **Generate Root Certificate Authority**:
   ```bash
   python3 scripts/gen_ca.py --outdir certs --cn "SecureChat Root CA"
   ```
   This creates:
   - `certs/ca.key.pem` - CA private key (KEEP SECURE, DO NOT COMMIT)
   - `certs/ca.cert.pem` - CA certificate

2. **Generate Server Certificate**:
   ```bash
   python3 scripts/gen_cert.py \
     --ca-key certs/ca.key.pem \
     --ca-cert certs/ca.cert.pem \
     --cn server.example \
     --outdir certs \
     --type server
   ```
   This creates:
   - `certs/server.example.key.pem` - Server private key
   - `certs/server.example.cert.pem` - Server certificate

3. **Generate Client Certificate**:
   ```bash
   python3 scripts/gen_cert.py \
     --ca-key certs/ca.key.pem \
     --ca-cert certs/ca.cert.pem \
     --cn client.example \
     --outdir certs \
     --type client
   ```
   This creates:
   - `certs/client.example.key.pem` - Client private key
   - `certs/client.example.cert.pem` - Client certificate

## Database Initialization

Initialize the database schema:

```bash
python -c "from db.db import init_schema; init_schema()"
```

This creates the `users` table with the following structure:
- `id`: Auto-increment primary key
- `email`: User email address
- `username`: Unique username
- `salt`: 16-byte random salt (VARBINARY)
- `pwd_hash`: SHA-256 hash of salted password (CHAR(64))
- `created_at`: Timestamp of account creation

## Running the System

### Start the Server

In one terminal:

```bash
python3 server.py \
  --server-cert certs/server.example.cert.pem \
  --server-key certs/server.example.key.pem \
  --ca-cert certs/ca.cert.pem \
  --bind 127.0.0.1 \
  --port 9000
```

The server will listen for incoming connections and display connection information.

### Run the Client

In another terminal:

**For Registration** (first time):
```bash
python3 client.py \
  --client-cert certs/client.example.cert.pem \
  --client-key certs/client.example.key.pem \
  --ca-cert certs/ca.cert.pem \
  --mode register \
  --email user@example.com \
  --username myuser \
  --password mypassword \
  --host 127.0.0.1 \
  --port 9000
```

**For Login** (subsequent sessions):
```bash
python3 client.py \
  --client-cert certs/client.example.cert.pem \
  --client-key certs/client.example.key.pem \
  --ca-cert certs/ca.cert.pem \
  --mode login \
  --email user@example.com \
  --password mypassword \
  --host 127.0.0.1 \
  --port 9000
```

After successful authentication, you can type messages in the console. Type `/quit` to exit.

## Security Features

### Certificate Validation
- Both client and server verify each other's certificates
- Checks include: signature chain validation, expiry date, validity period
- Invalid, expired, or self-signed certificates are rejected with "BAD CERT" error

### Password Security
- Passwords are never transmitted in plaintext
- Each user has a unique 16-byte random salt
- Passwords are hashed using SHA-256: `hex(SHA256(salt || password))`
- Constant-time comparison prevents timing attacks

### Message Protection
- **Confidentiality**: AES-128 encryption in CBC mode with PKCS#7 padding
- **Integrity**: SHA-256 hash of message metadata and ciphertext
- **Authenticity**: RSA signature over the hash using sender's private key
- **Freshness**: Sequence numbers and timestamps prevent replay attacks

### Non-Repudiation
- All messages are logged in append-only transcript files
- Each session generates a signed receipt containing:
  - Session identifier
  - Sequence number range
  - SHA-256 hash of the complete transcript
  - RSA signature over the transcript hash
- Transcripts can be verified offline using the participant's certificate

## File Structure

```
securechat_starter/
├── server.py              # Server implementation
├── client.py              # Client implementation
├── auth.py                # Password hashing utilities
├── db/
│   └── db.py              # Database connection and user management
├── scripts/
│   ├── gen_ca.py          # Root CA generation
│   └── gen_cert.py        # Certificate generation
├── certs/                 # Certificate storage (add to .gitignore)
│   ├── ca.key.pem         # CA private key (DO NOT COMMIT)
│   ├── ca.cert.pem        # CA certificate
│   ├── server.example.key.pem
│   ├── server.example.cert.pem
│   ├── client.example.key.pem
│   └── client.example.cert.pem
└── transcripts/           # Session transcripts and receipts
    ├── client_transcript_*.log
    ├── client_receipt_*.json
    ├── server_transcript_*.log
    └── server_receipt_*.json
```

## Testing and Evidence

### Wireshark Capture
Capture network traffic to verify encrypted payloads:
- Use display filter: `tcp.port == 9000`
- Verify that no plaintext credentials or messages are visible
- All application data should appear as encrypted binary

### Invalid Certificate Test
Test certificate validation by:
1. Creating a self-signed certificate
2. Attempting connection - should receive "BAD CERT" error
3. Using an expired certificate - should be rejected

### Tampering Test
1. Capture a message in Wireshark
2. Modify a single bit in the ciphertext
3. Resend the message - signature verification should fail

### Replay Test
1. Capture a valid message with sequence number N
2. Resend the same message - should be rejected as replay (sequence number <= last_seqno)

### Non-Repudiation Verification
1. Export session transcript and receipt files
2. Verify each message signature:
   ```python
   # Pseudocode
   hash = SHA256(seqno || timestamp || ciphertext)
   verify_signature(hash, signature, sender_certificate)
   ```
3. Verify receipt signature:
   ```python
   transcript_hash = SHA256(concatenate_all_transcript_lines)
   verify_signature(transcript_hash, receipt_signature, participant_certificate)
   ```
4. Modify transcript - receipt signature should fail

## Important Security Notes

- **Never commit private keys to Git**: Add `certs/*.key.pem` to `.gitignore`
- **Keep CA private key secure**: Compromise of CA key allows certificate forgery
- **Use strong database passwords**: Protect user credential hashes
- **Regular certificate rotation**: Renew certificates before expiry
- **Secure transcript storage**: Transcripts contain encrypted messages and signatures

## Troubleshooting

### Database Connection Errors
- Verify MySQL/MariaDB is running
- Check environment variables (DB_HOST, DB_USER, DB_PASS, DB_NAME)
- Ensure database and user exist with proper permissions

### Certificate Verification Failures
- Verify certificates are signed by the same CA
- Check certificate expiry dates
- Ensure certificate files are readable

### Authentication Failures
- Verify user exists in database (for login)
- Check password is correct
- Ensure username is unique (for registration)

## License and Academic Integrity

This implementation is provided for educational purposes. When submitting assignments:

- Ensure all code is your own work or properly cited
- Do not share private keys or credentials
- Follow your institution's academic integrity policies
- Document any external code snippets used

## References

- SEED Security Lab: Public Key Infrastructure
- Cryptography library documentation: https://cryptography.io/
- PyMySQL documentation: https://pymysql.readthedocs.io/
