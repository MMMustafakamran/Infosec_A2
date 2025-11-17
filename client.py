"""
Secure Chat Client Implementation
Implements a console-based secure chat client with:
- X.509 certificate-based mutual authentication
- Diffie-Hellman key exchange for session key derivation
- AES-128 encryption for message confidentiality
- RSA signatures for message integrity and authenticity
- Session transcripts and receipts for non-repudiation
"""
import socket
import json
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


def main():
    """Main client entry point."""
    create_transcript_directory()

    argument_parser = argparse.ArgumentParser(
        description="Secure Chat Client with CIANR protection"
    )
    argument_parser.add_argument("--host", default="127.0.0.1", help="Server hostname")
    argument_parser.add_argument("--port", type=int, default=9000, help="Server port")
    argument_parser.add_argument(
        "--client-cert",
        default="certs/client.example.cert.pem",
        help="Client certificate file"
    )
    argument_parser.add_argument(
        "--client-key",
        default="certs/client.example.key.pem",
        help="Client private key file"
    )
    argument_parser.add_argument(
        "--ca-cert",
        default="certs/ca.cert.pem",
        help="CA certificate file"
    )

    # Authentication options
    argument_parser.add_argument(
        "--mode",
        choices=["register", "login"],
        default="login",
        help="Authentication mode: register new user or login existing user"
    )
    argument_parser.add_argument("--email", help="User email address")
    argument_parser.add_argument("--username", help="Username (required for registration)")
    argument_parser.add_argument("--password", help="User password")

    client_config = argument_parser.parse_args()

    # Validate required arguments
    if not client_config.email or not client_config.password:
        raise SystemExit(
            "Error: --email and --password are required. "
            "For registration, --username is also required."
        )

    if client_config.mode == "register" and not client_config.username:
        raise SystemExit("Error: --username is required when using --mode register")

    # Establish TCP connection to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((client_config.host, client_config.port))
    except ConnectionRefusedError:
        raise SystemExit(f"Error: Could not connect to {client_config.host}:{client_config.port}")

    # Phase 1: Send client hello with certificate
    client_cert_pem = read_certificate_file(client_config.client_cert)
    client_nonce = secrets.token_bytes(16)
    
    client_hello_message = {
        "type": "hello",
        "client_cert": base64.b64encode(client_cert_pem).decode(),
        "nonce": base64.b64encode(client_nonce).decode(),
    }
    client_socket.send(json.dumps(client_hello_message).encode())

    # Phase 2: Receive server hello and verify server certificate
    server_hello_data = client_socket.recv(65536)
    try:
        server_hello = json.loads(server_hello_data.decode())
    except json.JSONDecodeError:
        print("Error: Invalid JSON in server hello")
        client_socket.close()
        return

    server_cert_pem = base64.b64decode(server_hello["server_cert"])
    server_nonce = base64.b64decode(server_hello["nonce"])

    # Load CA certificate and verify server certificate
    ca_certificate = x509.load_pem_x509_certificate(
        Path(client_config.ca_cert).read_bytes(),
        backend=default_backend()
    )
    server_certificate = x509.load_pem_x509_certificate(
        server_cert_pem,
        backend=default_backend()
    )
    
    ca_public_key = ca_certificate.public_key()
    try:
        ca_public_key.verify(
            server_certificate.signature,
            server_certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server_certificate.signature_hash_algorithm,
        )
        
        # Check certificate validity period
        current_time = time.time()
        not_before = server_certificate.not_valid_before.timestamp()
        not_after = server_certificate.not_valid_after.timestamp()
        
        if current_time < not_before or current_time > not_after:
            raise ValueError("Server certificate is expired or not yet valid")
        
        print("Server certificate verified successfully")
    except Exception as cert_error:
        print(f"Error: Server certificate verification failed: {cert_error}")
        client_socket.close()
        return

    server_cert_fingerprint = compute_certificate_fingerprint(server_certificate)

    # Phase 3: Receive Diffie-Hellman parameters from server
    dh_params_data = client_socket.recv(65536)
    try:
        dh_params_message = json.loads(dh_params_data.decode())
    except json.JSONDecodeError:
        print("Error: Invalid JSON in DH parameters")
        client_socket.close()
        return

    prime_p = int(dh_params_message["p"])
    generator_g = int(dh_params_message["g"])
    server_public_bytes = base64.b64decode(dh_params_message["server_pub"])
    server_public_int = int.from_bytes(server_public_bytes, "big")

    # Phase 4: Generate client's DH key pair and send public value
    dh_parameter_numbers = dh.DHParameterNumbers(prime_p, generator_g)
    dh_parameters = dh_parameter_numbers.parameters(backend=default_backend())
    
    client_dh_private = dh_parameters.generate_private_key()
    client_dh_public = client_dh_private.public_key()
    
    client_public_value = client_dh_public.public_numbers().y
    client_public_bytes = client_public_value.to_bytes(
        (client_public_value.bit_length() + 7) // 8,
        "big"
    )
    
    client_dh_message = {
        "type": "client_pub",
        "client_pub": base64.b64encode(client_public_bytes).decode()
    }
    client_socket.send(json.dumps(client_dh_message).encode())

    # Compute shared secret and derive session key
    server_public_numbers = dh.DHPublicNumbers(
        server_public_int,
        dh_parameters.parameter_numbers()
    )
    server_public_key = server_public_numbers.public_key(backend=default_backend())
    
    shared_secret = client_dh_private.exchange(server_public_key)
    session_encryption_key = compute_session_key(shared_secret)

    # Phase 5: Authentication (registration or login)
    auth_data = {
        "type": client_config.mode,
        "email": client_config.email,
        "password": client_config.password,
    }
    if client_config.mode == "register":
        auth_data["username"] = client_config.username

    auth_data_bytes = json.dumps(auth_data).encode()
    encrypted_auth = encrypt_with_aes(session_encryption_key, auth_data_bytes)
    
    auth_message = {
        "type": "auth",
        "ct": base64.b64encode(encrypted_auth).decode()
    }
    client_socket.send(json.dumps(auth_message).encode())

    # Receive authentication response
    auth_response_data = client_socket.recv(65536)
    try:
        auth_response = json.loads(auth_response_data.decode())
    except json.JSONDecodeError:
        print("Error: Invalid JSON in authentication response")
        client_socket.close()
        return

    if auth_response.get("type") != "auth_resp":
        print(f"Error: Expected auth_resp, received: {auth_response}")
        client_socket.close()
        return

    encrypted_response = base64.b64decode(auth_response["ct"])
    decrypted_response = decrypt_with_aes(session_encryption_key, encrypted_response)
    auth_result = json.loads(decrypted_response.decode())
    
    print(f"Authentication result: {auth_result}")

    if auth_result.get("status") != "ok":
        print("Authentication failed, cannot proceed to chat")
        client_socket.close()
        return

    # Phase 6: Interactive chat loop
    # Load client's private key for message signing
    client_private_key = serialization.load_pem_private_key(
        Path(client_config.client_key).read_bytes(),
        password=None,
        backend=default_backend()
    )

    message_sequence_number = 0
    session_transcript = []
    first_sequence = None
    last_sequence = None
    unique_session_id = secrets.token_hex(8)
    transcript_file_path = os.path.join(
        SESSION_TRANSCRIPTS_DIR,
        f"client_transcript_{unique_session_id}.log"
    )

    print("Chat session started. Type messages and press Enter.")
    print("Type /quit to exit the chat session.")

    try:
        while True:
            try:
                user_input = input("> ")
            except (EOFError, KeyboardInterrupt):
                print("\nExiting chat session...")
                break

            if user_input.strip() == "/quit":
                print("Exiting chat session...")
                break

            if not user_input.strip():
                continue

            message_sequence_number += 1
            message_timestamp = int(time.time() * 1000)
            message_plaintext = user_input.encode("utf-8")

            # Encrypt message
            message_ciphertext = encrypt_with_aes(session_encryption_key, message_plaintext)

            # Compute message hash and sign
            # Hash: SHA256(seqno || timestamp || ciphertext)
            hash_input = (str(message_sequence_number) + str(message_timestamp)).encode() + message_ciphertext
            message_hash = hashlib.sha256(hash_input).digest()
            message_signature = client_private_key.sign(
                message_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            # Send encrypted and signed message
            chat_message = {
                "type": "msg",
                "seqno": message_sequence_number,
                "ts": message_timestamp,
                "ct": base64.b64encode(message_ciphertext).decode(),
                "sig": base64.b64encode(message_signature).decode(),
            }
            client_socket.send(json.dumps(chat_message).encode())
            print(f"Message sent (seqno={message_sequence_number})")

            # Append to session transcript
            ciphertext_b64 = base64.b64encode(message_ciphertext).decode()
            signature_b64 = base64.b64encode(message_signature).decode()
            transcript_line = (
                f"{message_sequence_number}|{message_timestamp}|{ciphertext_b64}|"
                f"{signature_b64}|{server_cert_fingerprint}\n"
            )
            session_transcript.append(transcript_line.encode())

            # Write to append-only transcript file
            with open(transcript_file_path, "ab") as transcript_file:
                transcript_file.write(transcript_line.encode())

            if first_sequence is None:
                first_sequence = message_sequence_number
            last_sequence = message_sequence_number

    finally:
        # Phase 7: Generate session receipt for non-repudiation
        if session_transcript and first_sequence is not None and last_sequence is not None:
            transcript_content = b"".join(session_transcript)
            transcript_hash = hashlib.sha256(transcript_content).digest()
            transcript_hash_hex = transcript_hash.hex()

            session_receipt = {
                "type": "receipt",
                "side": "client",
                "peer": "server",
                "session_id": unique_session_id,
                "first_seq": first_sequence,
                "last_seq": last_sequence,
                "transcript_sha256": transcript_hash_hex,
                "peer_cert_fingerprint": server_cert_fingerprint,
            }

            receipt_signature = client_private_key.sign(
                transcript_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            session_receipt["sig"] = base64.b64encode(receipt_signature).decode()

            receipt_file_path = os.path.join(
                SESSION_TRANSCRIPTS_DIR,
                f"client_receipt_{unique_session_id}.json"
            )
            with open(receipt_file_path, "w", encoding="utf-8") as receipt_file:
                json.dump(session_receipt, receipt_file, indent=2)
            print(f"Client session receipt written to {receipt_file_path}")

        client_socket.close()


if __name__ == "__main__":
    main()
