# Secure Chat System Implementation Report
## Assignment 02 - Information Security

**Roll Number:** i221013  
**Name:** Mustafa Kamran  
**Course:** Information Security  
**Assignment:** A02 - Secure Chat System with CIANR Protection

---

## Table of Contents

1. [Introduction](#introduction)
2. [System Architecture](#system-architecture)
3. [Implementation Details](#implementation-details)
4. [Security Features](#security-features)
5. [Testing and Validation](#testing-and-validation)
6. [Conclusion](#conclusion)
7. [References](#references)

---

## 1. Introduction

### 1.1 Objective

This report documents the design and implementation of a console-based secure chat system that achieves Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR) through the integration of cryptographic primitives including AES-128, RSA with X.509 certificates, Diffie-Hellman key exchange, and SHA-256 hashing.

### 1.2 Threat Model

The system is designed to protect against:

- **Passive Eavesdroppers**: Adversaries who can observe network traffic
- **Active Man-in-the-Middle (MitM)**: Attackers who can intercept, modify, replay, or inject messages
- **Untrusted Clients**: Malicious clients attempting unauthorized access through login/password guessing

### 1.3 Security Goals

The implementation ensures:

- **Confidentiality**: All messages are encrypted using AES-128
- **Integrity**: Message tampering is detected through cryptographic hashing
- **Authenticity**: Both parties are authenticated using X.509 certificates
- **Non-Repudiation**: Signed session transcripts provide verifiable evidence of communication

---

## 2. System Architecture

### 2.1 Protocol Overview

The secure chat protocol operates in four distinct phases:

1. **Control Plane (Negotiation and Authentication)**: Certificate exchange and mutual verification
2. **Key Agreement**: Diffie-Hellman key exchange for session key derivation
3. **Data Plane (Encrypted Communication)**: Secure message exchange with integrity protection
4. **Tear Down (Non-Repudiation)**: Session transcript and receipt generation

### 2.2 System Components

#### 2.2.1 Certificate Authority (CA)

- **Location**: `scripts/gen_ca.py`
- **Function**: Generates root CA private key and self-signed certificate
- **Output**: 
  - `certs/ca.key.pem` - CA private key (4096-bit RSA)
  - `certs/ca.cert.pem` - CA self-signed certificate (valid for 10 years)

#### 2.2.2 Certificate Issuance

- **Location**: `scripts/gen_cert.py`
- **Function**: Issues X.509 certificates for server and client entities
- **Features**:
  - RSA key pair generation (3072-bit)
  - Certificate signing by root CA
  - Extended Key Usage extensions (SERVER_AUTH, CLIENT_AUTH)
  - Validity period: 825 days

#### 2.2.3 Server Component

- **Location**: `server.py`
- **Function**: Handles client connections, authentication, and message routing
- **Features**:
  - Multi-threaded client handling
  - Certificate validation and mutual authentication
  - Encrypted authentication processing
  - Message decryption and signature verification
  - Session transcript management

#### 2.2.4 Client Component

- **Location**: `client.py`
- **Function**: Interactive chat client with secure communication
- **Features**:
  - Certificate-based authentication
  - Encrypted message composition and transmission
  - Message signing and verification
  - Session transcript logging

#### 2.2.5 Database Module

- **Location**: `db/db.py`
- **Function**: MySQL/MariaDB integration for user management
- **Schema**: 
  ```sql
  CREATE TABLE users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL,
      username VARCHAR(255) UNIQUE NOT NULL,
      salt VARBINARY(16) NOT NULL,
      pwd_hash CHAR(64) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
  ```

#### 2.2.6 Authentication Module

- **Location**: `auth.py`
- **Function**: Password hashing and verification utilities
- **Algorithm**: SHA-256 with per-user random salts

---

## 3. Implementation Details

### 3.1 Public Key Infrastructure (PKI) Setup

#### 3.1.1 Root CA Generation

The root CA is generated using the `gen_ca.py` script:

```python
# Key generation: 4096-bit RSA with public exponent 65537
ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)

# Self-signed certificate with BasicConstraints extension
ca_certificate = (
    x509.CertificateBuilder()
    .subject_name(subject_name)
    .issuer_name(subject_name)  # Self-signed
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
)
```

#### 3.1.2 Certificate Validation

Both client and server perform mutual certificate verification:

1. **Signature Chain Validation**: Verify certificate is signed by trusted CA
2. **Expiry Check**: Validate certificate is within validity period
3. **Error Handling**: Reject invalid certificates with "BAD CERT" error

**Implementation**:
```python
def validate_certificate_chain(cert_pem_bytes, trusted_ca_cert):
    parsed_cert = x509.load_pem_x509_certificate(cert_pem_bytes, ...)
    ca_public_key = trusted_ca_cert.public_key()
    
    # Verify signature
    ca_public_key.verify(
        parsed_cert.signature,
        parsed_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        parsed_cert.signature_hash_algorithm,
    )
    
    # Check validity period
    current_time = time.time()
    if current_time < not_before or current_time > not_after:
        raise ValueError("Certificate is expired or not yet valid")
```

### 3.2 Registration and Login Security

#### 3.2.1 Password Hashing

Passwords are protected using salted SHA-256 hashing:

- **Salt Generation**: 16-byte cryptographically random salt per user
- **Hash Computation**: `pwd_hash = hex(SHA256(salt || password))`
- **Storage**: Salt stored as VARBINARY(16), hash as CHAR(64) in MySQL

**Implementation**:
```python
def compute_password_hash(password: str, salt: bytes) -> str:
    password_bytes = password.encode("utf-8")
    hash_digest = hashlib.sha256(salt + password_bytes).hexdigest()
    return hash_digest
```

#### 3.2.2 Encrypted Credential Transmission

Credentials are never transmitted in plaintext:

1. **Initial DH Exchange**: Temporary Diffie-Hellman key exchange
2. **AES Key Derivation**: `K = Trunc16(SHA256(big-endian(Ks)))`
3. **Encryption**: Registration/login data encrypted with AES-128 before transmission
4. **Server Decryption**: Server decrypts and processes authentication

**Message Format**:
```json
{
  "type": "auth",
  "ct": "base64(encrypted_json_payload)"
}
```

Where `encrypted_json_payload` contains:
```json
{
  "type": "register|login",
  "email": "user@example.com",
  "username": "myuser",  // for registration only
  "password": "plaintext_password"  // only inside encrypted channel
}
```

### 3.3 Session Key Establishment

#### 3.3.1 Diffie-Hellman Key Exchange

After successful authentication, a new DH exchange establishes the chat session key:

1. **Server Generates Parameters**: Prime p and generator g (2048-bit)
2. **Public Value Exchange**: 
   - Server: A = g^a mod p
   - Client: B = g^b mod p
3. **Shared Secret**: Ks = B^a mod p = A^b mod p
4. **Session Key**: K = Trunc16(SHA256(big-endian(Ks)))

**Implementation**:
```python
# Server side
dh_parameters = dh.generate_parameters(generator=2, key_size=2048, ...)
server_dh_private = dh_parameters.generate_private_key()
shared_secret = server_dh_private.exchange(client_public_key)

# Key derivation
def compute_session_key(shared_secret_bytes):
    hash_output = hashlib.sha256(shared_secret_bytes).digest()
    return hash_output[:16]  # AES-128 requires 16 bytes
```

### 3.4 Encrypted Message Exchange

#### 3.4.1 Message Encryption

Each chat message is encrypted using AES-128 in CBC mode:

1. **Padding**: PKCS#7 padding applied to plaintext
2. **IV Generation**: 16-byte random initialization vector
3. **Encryption**: AES-128-CBC encryption
4. **Transmission**: IV prepended to ciphertext

**Implementation**:
```python
def encrypt_with_aes(session_key, message_bytes: bytes) -> bytes:
    initialization_vector = secrets.token_bytes(16)
    padding_obj = sym_padding.PKCS7(128).padder()
    padded_data = padding_obj.update(message_bytes) + padding_obj.finalize()
    
    cipher_obj = Cipher(
        algorithms.AES(session_key),
        modes.CBC(initialization_vector),
        backend=default_backend()
    )
    encryptor = cipher_obj.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return initialization_vector + ciphertext
```

#### 3.4.2 Message Integrity and Authenticity

Each message includes a digital signature for integrity and authenticity:

1. **Hash Computation**: `h = SHA256(seqno || timestamp || ciphertext)`
2. **Signature Generation**: `sig = RSA_SIGN(h)` using sender's private key
3. **Verification**: Recipient recomputes hash and verifies signature

**Message Format**:
```json
{
  "type": "msg",
  "seqno": 1,
  "ts": 1234567890123,
  "ct": "base64(ciphertext)",
  "sig": "base64(rsa_signature)"
}
```

**Implementation**:
```python
# Sender side
hash_input = (str(seqno) + str(timestamp)).encode() + ciphertext
message_hash = hashlib.sha256(hash_input).digest()
message_signature = sender_private_key.sign(
    message_hash,
    padding.PKCS1v15(),
    hashes.SHA256()
)

# Receiver side
client_public_key.verify(
    message_signature,
    message_hash,
    padding.PKCS1v15(),
    hashes.SHA256()
)
```

#### 3.4.3 Replay Protection

Sequence numbers prevent replay attacks:

- **Strictly Increasing**: Each message must have seqno > last_seqno
- **Rejection**: Messages with seqno <= last_seqno are rejected
- **Timestamp**: Additional freshness check using Unix timestamp (milliseconds)

**Implementation**:
```python
if sequence_number <= expected_sequence_number:
    print(f"REPLAY or OUT-OF-ORDER detected: "
          f"received seqno={sequence_number}, expected >{expected_sequence_number}")
    break
```

### 3.5 Non-Repudiation

#### 3.5.1 Session Transcripts

Both client and server maintain append-only transcript files:

**Transcript Format**:
```
seqno|timestamp|ciphertext_base64|signature_base64|peer_cert_fingerprint
```

**Example**:
```
1|1234567890123|aGVsbG8gd29ybGQ=|MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...|abc123def456
2|1234567890456|Z29vZGJ5ZQ==|MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8B...|abc123def456
```

#### 3.5.2 Session Receipts

At session end, each participant generates a signed receipt:

1. **Transcript Hash**: `TranscriptHash = SHA256(concatenation of all transcript lines)`
2. **Receipt Signing**: Receipt hash signed with participant's RSA private key
3. **Receipt Format**:
```json
{
  "type": "receipt",
  "side": "client|server",
  "peer": "server|client",
  "session_id": "unique_session_id",
  "first_seq": 1,
  "last_seq": 10,
  "transcript_sha256": "hex_hash",
  "peer_cert_fingerprint": "cert_fingerprint",
  "sig": "base64(rsa_signature)"
}
```

**Offline Verification**:
1. Recompute transcript hash from transcript file
2. Verify receipt signature using participant's certificate
3. Confirm hash matches receipt transcript_sha256
4. Any modification to transcript invalidates the receipt

---

## 4. Security Features

### 4.1 Confidentiality

- **AES-128 Encryption**: All messages encrypted with 128-bit AES in CBC mode
- **Session Keys**: Unique session key per chat session via Diffie-Hellman
- **Encrypted Authentication**: Credentials encrypted before transmission
- **No Plaintext Transit**: No sensitive data transmitted in plaintext

### 4.2 Integrity

- **SHA-256 Hashing**: Cryptographic hash over message metadata and ciphertext
- **Digital Signatures**: RSA signatures prevent undetected tampering
- **Tamper Detection**: Any modification to ciphertext invalidates signature

### 4.3 Authenticity

- **X.509 Certificates**: Mutual certificate-based authentication
- **CA Validation**: Certificate chain validation ensures trusted identity
- **Certificate Expiry**: Expired certificates rejected
- **Per-Message Signatures**: Each message signed by sender's private key

### 4.4 Non-Repudiation

- **Signed Transcripts**: Session transcripts with cryptographic signatures
- **Receipt Generation**: Signed session receipts provide verifiable evidence
- **Offline Verification**: Receipts can be verified without server access
- **Append-Only Logs**: Transcript files are append-only, preventing modification

### 4.5 Additional Security Measures

- **Replay Protection**: Sequence numbers prevent message replay
- **Timestamp Validation**: Timestamps ensure message freshness
- **Constant-Time Comparison**: Password verification uses constant-time comparison
- **Random Salts**: Per-user random salts prevent rainbow table attacks
- **Secure Random Generation**: Cryptographically secure random number generation

---

## 5. Testing and Validation

### 5.1 Certificate Validation Tests

#### Test 1: Valid Certificate Acceptance
- **Procedure**: Connect with valid CA-signed certificate
- **Expected**: Connection accepted, authentication proceeds
- **Result**: ✅ PASS - Valid certificates accepted

#### Test 2: Invalid Certificate Rejection
- **Procedure**: Attempt connection with self-signed certificate
- **Expected**: "BAD CERT" error, connection rejected
- **Result**: ✅ PASS - Invalid certificates rejected

#### Test 3: Expired Certificate Rejection
- **Procedure**: Use certificate past validity period
- **Expected**: "BAD CERT" error, connection rejected
- **Result**: ✅ PASS - Expired certificates rejected

### 5.2 Message Integrity Tests

#### Test 4: Tampering Detection
- **Procedure**: 
  1. Capture valid message in Wireshark
  2. Modify single bit in ciphertext
  3. Resend modified message
- **Expected**: Signature verification fails, message rejected
- **Result**: ✅ PASS - Tampering detected

#### Test 5: Replay Attack Prevention
- **Procedure**:
  1. Capture message with seqno=5
  2. Resend same message after seqno=10
- **Expected**: Replay detected, message rejected (seqno <= last_seqno)
- **Result**: ✅ PASS - Replay attacks prevented

### 5.3 Wireshark Analysis

#### Network Traffic Analysis
- **Display Filter**: `tcp.port == 9000`
- **Observation**: All application data appears as encrypted binary
- **Verification**: No plaintext credentials or messages visible
- **Conclusion**: Confidentiality maintained in transit

### 5.4 Non-Repudiation Verification

#### Receipt Verification Process
1. **Extract Transcript**: Load session transcript file
2. **Recompute Hash**: `SHA256(concatenate_all_lines)`
3. **Verify Signature**: Use participant's certificate to verify receipt signature
4. **Hash Comparison**: Confirm computed hash matches receipt transcript_sha256
5. **Modification Test**: Modify transcript → receipt signature fails

**Result**: ✅ PASS - Receipts provide verifiable non-repudiation

---

## 6. Conclusion

### 6.1 Summary

This implementation successfully demonstrates the integration of cryptographic primitives to achieve CIANR (Confidentiality, Integrity, Authenticity, and Non-Repudiation) in a practical secure chat system. The system provides:

- **Secure Authentication**: Certificate-based mutual authentication with encrypted credential transmission
- **Confidential Communication**: AES-128 encrypted messages with unique session keys
- **Message Integrity**: RSA signatures ensure message authenticity and prevent tampering
- **Replay Protection**: Sequence numbers and timestamps prevent replay attacks
- **Non-Repudiation**: Signed session transcripts and receipts provide verifiable evidence

### 6.2 Key Achievements

1. ✅ Complete PKI implementation with root CA and certificate issuance
2. ✅ Mutual certificate verification with expiry checking
3. ✅ Encrypted authentication with salted password hashing
4. ✅ Diffie-Hellman key exchange for session key derivation
5. ✅ AES-128 encryption with PKCS#7 padding
6. ✅ RSA signatures for message integrity
7. ✅ Sequence number-based replay protection
8. ✅ Session transcripts and signed receipts for non-repudiation

### 6.3 Compliance with Requirements

All assignment requirements have been fulfilled:

- **PKI Setup**: ✅ Root CA, certificate issuance, mutual verification
- **Registration & Login**: ✅ Encrypted credentials, salted hashing, MySQL storage
- **Key Agreement**: ✅ Diffie-Hellman with correct key derivation
- **Encrypted Chat**: ✅ AES-128 with integrity and authenticity
- **Non-Repudiation**: ✅ Transcripts and signed receipts
- **Testing**: ✅ Evidence collection and validation

### 6.4 Future Enhancements

Potential improvements for production deployment:

1. **Perfect Forward Secrecy**: Implement ephemeral keys for each message
2. **Key Rotation**: Periodic session key renewal during long sessions
3. **Certificate Revocation**: Implement CRL or OCSP for certificate revocation
4. **Rate Limiting**: Prevent brute-force attacks on authentication
5. **Audit Logging**: Enhanced logging for security monitoring
6. **Multi-User Support**: Extend to support multiple concurrent chat sessions

---

## 7. References

1. SEED Security Lab: Public Key Infrastructure - https://seedsecuritylabs.org/
2. Cryptography Library Documentation - https://cryptography.io/
3. PyMySQL Documentation - https://pymysql.readthedocs.io/
4. RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
5. NIST Special Publication 800-57: Recommendation for Key Management
6. Applied Cryptography by Bruce Schneier

---

## Appendix A: Certificate Inspection

### A.1 CA Certificate

```bash
openssl x509 -in certs/ca.cert.pem -text -noout
```

**Key Fields**:
- **Subject**: CN=SecureChat Root CA
- **Issuer**: CN=SecureChat Root CA (self-signed)
- **Validity**: 10 years
- **Basic Constraints**: CA=TRUE
- **Signature Algorithm**: sha256WithRSAEncryption

### A.2 Server Certificate

```bash
openssl x509 -in certs/server.example.cert.pem -text -noout
```

**Key Fields**:
- **Subject**: CN=server.example
- **Issuer**: CN=SecureChat Root CA
- **Extended Key Usage**: TLS Web Server Authentication
- **Basic Constraints**: CA=FALSE

### A.3 Client Certificate

```bash
openssl x509 -in certs/client.example.cert.pem -text -noout
```

**Key Fields**:
- **Subject**: CN=client.example
- **Issuer**: CN=SecureChat Root CA
- **Extended Key Usage**: TLS Web Client Authentication
- **Basic Constraints**: CA=FALSE

---

## Appendix B: Database Schema

### B.1 Users Table

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### B.2 Sample Records

```sql
INSERT INTO users (email, username, salt, pwd_hash) VALUES
('user1@example.com', 'user1', 0x1234..., 'a1b2c3d4...'),
('user2@example.com', 'user2', 0x5678..., 'e5f6g7h8...');
```

---

## Appendix C: GitHub Repository

**Repository URL**: https://github.com/MMMustafakamran/Infosec_A2.git

**Commit History**: 10 meaningful commits showing progressive development:
1. Initial project structure
2. CA generation script
3. Certificate issuance script
4. Database module
5. Authentication utilities
6. Server implementation
7. Client implementation
8. Development documentation
9. Package initialization
10. Final implementation

---

**End of Report**

