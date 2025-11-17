# Development Commit Plan

This document outlines a suggested commit-by-commit development approach that aligns with the assignment rubric requirements. Each commit should represent a logical, atomic change to the codebase.

## Commit Sequence (Minimum 10 Commits)

### 1. Project Initialization
- Create project structure
- Add README.md with project overview
- Add .gitignore to exclude sensitive files (private keys, certificates)
- Set up basic directory structure (certs/, transcripts/, db/, scripts/)

### 2. Certificate Authority Generation
- Implement `scripts/gen_ca.py`
- Generate root CA private key and self-signed certificate
- Add documentation for CA generation process

### 3. Certificate Issuance Script
- Implement `scripts/gen_cert.py`
- Support for server and client certificate generation
- Certificate signing by root CA
- Add usage documentation

### 4. Database Schema and Connection
- Implement `db/db.py` module
- Create database connection helper functions
- Implement `init_schema()` for users table creation
- Add MySQL/MariaDB integration

### 5. Server Certificate Exchange
- Implement server-side certificate loading and exchange
- Add mutual certificate verification logic
- Implement CA certificate validation
- Add certificate expiry and validity checks

### 6. Client Certificate Exchange
- Implement client-side certificate loading and exchange
- Add server certificate verification
- Implement nonce generation and exchange
- Complete mutual authentication handshake

### 7. Diffie-Hellman Key Exchange
- Implement DH parameter generation and exchange
- Add shared secret computation
- Implement session key derivation: `K = Trunc16(SHA256(big-endian(Ks)))`
- Add AES-128 key derivation logic

### 8. AES Encryption Implementation
- Implement AES-128 encryption with CBC mode
- Add PKCS#7 padding support
- Implement AES decryption with unpadding
- Add IV generation and management

### 9. Authentication System
- Implement `auth.py` with password hashing utilities
- Add salted SHA-256 password hashing
- Implement user registration with encrypted credentials
- Implement user login with credential verification
- Add constant-time password comparison

### 10. Message Integrity and Signatures
- Implement per-message SHA-256 hashing
- Add RSA signature generation using PKCS1v15
- Implement signature verification on received messages
- Add sequence number and timestamp to message format

### 11. Replay Protection
- Implement sequence number tracking
- Add strict sequence number validation
- Implement timestamp-based freshness checks
- Add replay detection and rejection logic

### 12. Session Transcripts
- Implement append-only transcript logging
- Add transcript file generation (client and server)
- Include message metadata in transcripts
- Add peer certificate fingerprint to transcript entries

### 13. Non-Repudiation Receipts
- Implement SessionReceipt generation
- Add transcript hash computation (SHA-256)
- Implement receipt signing with RSA
- Export receipts in JSON format

### 14. Error Handling and Validation
- Add comprehensive error handling
- Implement certificate validation error messages
- Add authentication failure handling
- Improve error messages for debugging

### 15. Testing and Documentation
- Add test scripts for tampering detection
- Add replay attack test scenarios
- Add invalid certificate test cases
- Update README with complete usage instructions
- Add Wireshark capture guidelines

## Commit Best Practices

- **Atomic Commits**: Each commit should represent one logical change
- **Clear Messages**: Use descriptive commit messages explaining what and why
- **No Secrets**: Never commit private keys, passwords, or sensitive data
- **Test Before Commit**: Ensure code works before committing
- **Incremental Progress**: Build features incrementally, not all at once

## Rubric Alignment

This commit plan ensures coverage of all rubric categories:
- **PKI Setup**: Commits 2, 3, 5, 6
- **Registration & Login**: Commit 9
- **Key Agreement**: Commit 7
- **Encrypted Chat**: Commits 8, 10
- **Integrity & Non-Repudiation**: Commits 10, 11, 12, 13
- **Testing**: Commit 15
