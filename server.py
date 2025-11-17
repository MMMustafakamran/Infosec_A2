"""
Secure Chat Server Implementation
Implements a console-based secure chat server with:
- X.509 certificate-based mutual authentication
- Diffie-Hellman key exchange for session key derivation
- AES-128 encryption for message confidentiality
- RSA signatures for message integrity and authenticity
- Session transcripts and receipts for non-repudiation
"""
import socket
import json
import threading
import base64
import argparse
import secrets
import hashlib
import os
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

from db.db import create_user, get_user_by_email
import auth


SESSION_TRANSCRIPTS_DIR = "transcripts"


def create_transcript_directory():
    """Ensure the transcripts directory exists for storing session logs."""
    os.makedirs(SESSION_TRANSCRIPTS_DIR, exist_ok=True)


def read_certificate_file(filepath):
    """Read a PEM certificate file from disk."""
    return Path(filepath).read_bytes()


def compute_certificate_fingerprint(certificate: x509.Certificate) -> str:
    """Compute SHA-256 fingerprint of a certificate for identification."""
    return certificate.fingerprint(hashes.SHA256()).hex()


def validate_certificate_chain(cert_pem_bytes, trusted_ca_cert):
    """
    Verify that a certificate is signed by the trusted CA.
    Returns the parsed certificate if valid, raises exception otherwise.
    """
    parsed_cert = x509.load_pem_x509_certificate(cert_pem_bytes, backend=default_backend())
    ca_public_key = trusted_ca_cert.public_key()
    
    # Verify the certificate signature using CA's public key
    ca_public_key.verify(
        parsed_cert.signature,
        parsed_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        parsed_cert.signature_hash_algorithm,
    )
    
    # Check certificate validity period
    current_time = time.time()
    not_before = parsed_cert.not_valid_before.timestamp()
    not_after = parsed_cert.not_valid_after.timestamp()
    
    if current_time < not_before or current_time > not_after:
        raise ValueError("Certificate is expired or not yet valid")
    
    return parsed_cert


def compute_session_key(shared_secret_bytes):
    """
    Derive AES-128 session key from Diffie-Hellman shared secret.
    Uses SHA-256 hash truncated to 16 bytes (128 bits).
    """
    hash_output = hashlib.sha256(shared_secret_bytes).digest()
    return hash_output[:16]  # AES-128 requires 16 bytes


def encrypt_with_aes(session_key, message_bytes: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 in CBC mode with PKCS#7 padding.
    Returns IV prepended to ciphertext.
    """
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
    
    return initialization_vector + ciphertext  # Prepend IV for decryption


def decrypt_with_aes(session_key, encrypted_data: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 in CBC mode and remove PKCS#7 padding.
    Expects IV as first 16 bytes of encrypted_data.
    """
    initialization_vector = encrypted_data[:16]
    ciphertext_only = encrypted_data[16:]
    
    cipher_obj = Cipher(
        algorithms.AES(session_key),
        modes.CBC(initialization_vector),
        backend=default_backend()
    )
    decryptor = cipher_obj.decryptor()
    decrypted_padded = decryptor.update(ciphertext_only) + decryptor.finalize()
    
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    return plaintext


def process_authentication_request(connection_socket, encryption_key):
    """
    Handle encrypted authentication (registration or login) request.
    Returns True if authentication succeeds, False otherwise.
    """
    received_data = connection_socket.recv(65536)
    if not received_data:
        print("Client disconnected before authentication")
        return False

    try:
        message_json = json.loads(received_data.decode())
    except json.JSONDecodeError:
        print("Invalid JSON in authentication message")
        return False

    if message_json.get("type") != "auth":
        print(f"Expected auth message type, received: {message_json.get('type')}")
        return False

    encrypted_payload = base64.b64decode(message_json["ct"])
    try:
        decrypted_bytes = decrypt_with_aes(encryption_key, encrypted_payload)
        auth_data = json.loads(decrypted_bytes.decode())
    except Exception as e:
        print(f"Failed to decrypt or parse authentication data: {e}")
        return False

    request_type = auth_data.get("type")
    user_email = auth_data.get("email")
    user_password = auth_data.get("password")  # Only transmitted inside encrypted channel

    if request_type == "register":
        user_name = auth_data.get("username")
        print(f"Registration attempt: email={user_email}, username={user_name}")

        user_salt = auth.generate_salt()
        password_hash = auth.hash_password(user_password, user_salt)
        registration_success = create_user(user_email, user_name, user_salt, password_hash)
        
        if registration_success:
            response_status = "ok"
            response_message = "User registration completed successfully"
        else:
            response_status = "error"
            response_message = "Username already exists in database"

    elif request_type == "login":
        print(f"Login attempt: email={user_email}")
        user_record = get_user_by_email(user_email)
        
        if not user_record:
            response_status = "error"
            response_message = "User not found"
        else:
            stored_salt = user_record["salt"]  # bytes
            stored_password_hash = user_record["pwd_hash"]  # hex string
            
            if auth.verify_password(stored_salt, stored_password_hash, user_password):
                response_status = "ok"
                response_message = "Login successful"
            else:
                response_status = "error"
                response_message = "Incorrect password"
    else:
        response_status = "error"
        response_message = f"Unknown authentication type: {request_type}"

    # Send encrypted response
    response_data = {"status": response_status, "message": response_message}
    response_bytes = json.dumps(response_data).encode()
    encrypted_response = encrypt_with_aes(encryption_key, response_bytes)
    
    response_message = {
        "type": "auth_resp",
        "ct": base64.b64encode(encrypted_response).decode()
    }
    connection_socket.send(json.dumps(response_message).encode())

    print(f"Authentication result: {response_status} - {response_message}")
    return response_status == "ok"


def handle_client_connection(connection_socket, client_address, server_config):
    """
    Main handler for each client connection.
    Implements the complete secure chat protocol:
    1. Certificate exchange and validation
    2. Diffie-Hellman key exchange
    3. Authentication (registration/login)
    4. Encrypted message exchange with integrity verification
    5. Session transcript and receipt generation
    """
    print(f"New client connection from {client_address}")

    # Load server's private key for signing session receipts
    server_private_key = serialization.load_pem_private_key(
        Path(server_config.server_key).read_bytes(),
        password=None,
        backend=default_backend()
    )

    # Phase 1: Receive client hello with certificate
    client_hello_data = connection_socket.recv(65536)
    if not client_hello_data:
        print("Client disconnected immediately")
        connection_socket.close()
        return

    try:
        client_hello = json.loads(client_hello_data.decode())
    except json.JSONDecodeError:
        print("Invalid JSON in client hello")
        connection_socket.close()
        return

    client_cert_pem = base64.b64decode(client_hello["client_cert"])
    client_nonce = base64.b64decode(client_hello["nonce"])
    print(f"Received client hello, nonce length: {len(client_nonce)}")

    # Phase 2: Send server hello with certificate and nonce
    server_cert_pem = read_certificate_file(server_config.server_cert)
    
    with open(server_config.ca_cert, "rb") as ca_file:
        ca_certificate = x509.load_pem_x509_certificate(
            ca_file.read(),
            backend=default_backend()
        )

    # Verify client certificate
    try:
        client_certificate = validate_certificate_chain(client_cert_pem, ca_certificate)
        print(f"Client certificate verified successfully. Subject: {client_certificate.subject}")
    except Exception as cert_error:
        print(f"Client certificate verification failed: {cert_error}")
        error_response = json.dumps({"error": "BAD CERT"}).encode()
        connection_socket.send(error_response)
        connection_socket.close()
        return

    client_cert_fingerprint = compute_certificate_fingerprint(client_certificate)

    server_nonce = secrets.token_bytes(16)
    server_hello_message = {
        "type": "server_hello",
        "server_cert": base64.b64encode(server_cert_pem).decode(),
        "nonce": base64.b64encode(server_nonce).decode(),
    }
    connection_socket.send(json.dumps(server_hello_message).encode())

    # Phase 3: Diffie-Hellman key exchange
    # Server generates DH parameters and public key
    dh_parameters = dh.generate_parameters(
        generator=2,
        key_size=2048,
        backend=default_backend()
    )
    server_dh_private = dh_parameters.generate_private_key()
    server_dh_public = server_dh_private.public_key()
    
    param_values = dh_parameters.parameter_numbers()
    prime_p = param_values.p
    generator_g = param_values.g
    
    server_public_value = server_dh_public.public_numbers().y
    server_public_bytes = server_public_value.to_bytes(
        (server_public_value.bit_length() + 7) // 8,
        "big"
    )
    
    dh_params_message = {
        "type": "dh_params",
        "p": str(prime_p),
        "g": str(generator_g),
        "server_pub": base64.b64encode(server_public_bytes).decode(),
    }
    connection_socket.send(json.dumps(dh_params_message).encode())

    # Phase 4: Receive client's public value and compute shared secret
    client_dh_data = connection_socket.recv(65536)
    if not client_dh_data:
        print("Client disconnected before sending DH public value")
        connection_socket.close()
        return

    try:
        client_dh_message = json.loads(client_dh_data.decode())
    except json.JSONDecodeError:
        print("Invalid JSON in client DH message")
        connection_socket.close()
        return

    client_public_bytes = base64.b64decode(client_dh_message["client_pub"])
    client_public_int = int.from_bytes(client_public_bytes, "big")
    
    client_public_numbers = dh.DHPublicNumbers(
        client_public_int,
        dh_parameters.parameter_numbers()
    )
    client_public_key = client_public_numbers.public_key(backend=default_backend())
    
    shared_secret = server_dh_private.exchange(client_public_key)
    session_encryption_key = compute_session_key(shared_secret)
    print(f"Derived session encryption key, length: {len(session_encryption_key)} bytes")

    # Phase 5: Authentication (registration or login)
    if not process_authentication_request(connection_socket, session_encryption_key):
        print("Authentication failed, terminating connection")
        connection_socket.close()
        return

    # Phase 6: Encrypted chat message loop
    expected_sequence_number = 0
    session_transcript = []
    first_sequence = None
    last_sequence = None
    unique_session_id = secrets.token_hex(8)
    transcript_file_path = os.path.join(
        SESSION_TRANSCRIPTS_DIR,
        f"server_transcript_{unique_session_id}.log"
    )
    print(f"Starting chat session for {client_address}, session ID: {unique_session_id}")

    while True:
        message_data = connection_socket.recv(65536)
        if not message_data:
            print(f"Client {client_address} disconnected")
            break

        try:
            message_json = json.loads(message_data.decode())
        except json.JSONDecodeError as e:
            print(f"Invalid JSON from client: {e}")
            break

        if message_json.get("type") != "msg":
            print(f"Ignoring non-message type: {message_json.get('type')}")
            continue

        ciphertext = base64.b64decode(message_json["ct"])
        message_signature = base64.b64decode(message_json["sig"])
        sequence_number = message_json.get("seqno", 0)
        timestamp = message_json.get("ts", 0)

        # Replay protection: sequence numbers must be strictly increasing
        if sequence_number <= expected_sequence_number:
            print(
                f"REPLAY or OUT-OF-ORDER detected: "
                f"received seqno={sequence_number}, expected >{expected_sequence_number}"
            )
            break

        # Verify message signature
        try:
            client_public_key = client_certificate.public_key()
            # Compute hash: SHA256(seqno || timestamp || ciphertext)
            hash_input = (str(sequence_number) + str(timestamp)).encode() + ciphertext
            message_hash = hashlib.sha256(hash_input).digest()
            
            client_public_key.verify(
                message_signature,
                message_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print(f"Message signature verified for seqno={sequence_number}")
        except Exception as sig_error:
            print(f"Signature verification failed: {sig_error}")
            break

        # Decrypt message
        try:
            plaintext = decrypt_with_aes(session_encryption_key, ciphertext)
            print(
                f"[{client_address}] seq={sequence_number} ts={timestamp} "
                f"message: {plaintext.decode(errors='ignore')}"
            )
        except Exception as decrypt_error:
            print(f"Decryption failed: {decrypt_error}")
            break

        # Append to session transcript
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        signature_b64 = base64.b64encode(message_signature).decode()
        transcript_line = (
            f"{sequence_number}|{timestamp}|{ciphertext_b64}|"
            f"{signature_b64}|{client_cert_fingerprint}\n"
        )
        session_transcript.append(transcript_line.encode())

        # Write to append-only transcript file
        with open(transcript_file_path, "ab") as transcript_file:
            transcript_file.write(transcript_line.encode())

        if first_sequence is None:
            first_sequence = sequence_number
        last_sequence = sequence_number
        expected_sequence_number = sequence_number

    # Phase 7: Generate session receipt for non-repudiation
    if session_transcript and first_sequence is not None and last_sequence is not None:
        transcript_content = b"".join(session_transcript)
        transcript_hash = hashlib.sha256(transcript_content).digest()
        transcript_hash_hex = transcript_hash.hex()

        session_receipt = {
            "type": "receipt",
            "side": "server",
            "peer": "client",
            "session_id": unique_session_id,
            "first_seq": first_sequence,
            "last_seq": last_sequence,
            "transcript_sha256": transcript_hash_hex,
            "peer_cert_fingerprint": client_cert_fingerprint,
        }

        receipt_signature = server_private_key.sign(
            transcript_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        session_receipt["sig"] = base64.b64encode(receipt_signature).decode()

        receipt_file_path = os.path.join(
            SESSION_TRANSCRIPTS_DIR,
            f"server_receipt_{unique_session_id}.json"
        )
        with open(receipt_file_path, "w", encoding="utf-8") as receipt_file:
            json.dump(session_receipt, receipt_file, indent=2)
        print(f"Session receipt written to {receipt_file_path}")

    connection_socket.close()


def main():
    """Main server entry point."""
    create_transcript_directory()
    
    argument_parser = argparse.ArgumentParser(
        description="Secure Chat Server with CIANR protection"
    )
    argument_parser.add_argument("--bind", default="127.0.0.1", help="Bind address")
    argument_parser.add_argument("--port", type=int, default=9000, help="Listen port")
    argument_parser.add_argument(
        "--server-cert",
        default="certs/server.example.cert.pem",
        help="Server certificate file"
    )
    argument_parser.add_argument(
        "--server-key",
        default="certs/server.example.key.pem",
        help="Server private key file"
    )
    argument_parser.add_argument(
        "--ca-cert",
        default="certs/ca.cert.pem",
        help="CA certificate file"
    )
    config = argument_parser.parse_args()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((config.bind, config.port))
    server_socket.listen(5)
    
    print(f"Secure chat server listening on {config.bind}:{config.port}")
    
    try:
        while True:
            client_connection, client_address = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client_connection,
                args=(client_connection, client_address, config)
            )
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
