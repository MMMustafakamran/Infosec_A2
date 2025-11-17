#!/usr/bin/env python3
"""
Replay Attack Test Client
Tests the system's ability to detect and prevent message replay attacks.
Sends a valid message, then attempts to resend the same message with identical sequence number.

Expected Behavior:
- First message (seqno=1): Should be accepted and processed normally
- Second message (seqno=1, replayed): Should be rejected as replay/out-of-order
- Server should log "REPLAY or OUT-OF-ORDER detected"
"""
import socket
import json
import base64
import secrets
import hashlib
import time
import argparse
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


def read_certificate_file(filepath):
    """Read a PEM certificate file from disk."""
    return Path(filepath).read_bytes()


def derive_session_key(shared_secret_bytes):
    """Derive AES-128 session key from Diffie-Hellman shared secret."""
    hash_output = hashlib.sha256(shared_secret_bytes).digest()
    return hash_output[:16]  # AES-128 requires 16 bytes


def encrypt_message(key, plaintext: bytes) -> bytes:
    """Encrypt plaintext using AES-128 in CBC mode with PKCS#7 padding."""
    initialization_vector = secrets.token_bytes(16)
    padding_obj = sym_padding.PKCS7(128).padder()
    padded_data = padding_obj.update(plaintext) + padding_obj.finalize()
    
    cipher_obj = Cipher(
        algorithms.AES(key),
        modes.CBC(initialization_vector),
        backend=default_backend()
    )
    encryptor = cipher_obj.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return initialization_vector + ciphertext


def main():
    """Main test execution function."""
    argument_parser = argparse.ArgumentParser(
        description="Test replay attack detection by resending messages"
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
    argument_parser.add_argument("--email", default="test@example.com", help="User email")
    argument_parser.add_argument("--password", default="mysecret", help="User password")
    
    test_config = argument_parser.parse_args()

    # Establish connection
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_socket.connect((test_config.host, test_config.port))

    # Phase 1: Certificate exchange
    client_cert_pem = read_certificate_file(test_config.client_cert)
    client_nonce = secrets.token_bytes(16)
    
    client_hello = {
        "type": "hello",
        "client_cert": base64.b64encode(client_cert_pem).decode(),
        "nonce": base64.b64encode(client_nonce).decode(),
    }
    test_socket.send(json.dumps(client_hello).encode())

    # Receive server hello
    server_hello_data = test_socket.recv(65536)
    server_hello = json.loads(server_hello_data.decode())
    server_cert_pem = base64.b64decode(server_hello["server_cert"])

    # Verify server certificate
    ca_certificate = x509.load_pem_x509_certificate(
        Path(test_config.ca_cert).read_bytes(),
        backend=default_backend()
    )
    server_certificate = x509.load_pem_x509_certificate(
        server_cert_pem,
        backend=default_backend()
    )
    ca_public_key = ca_certificate.public_key()
    ca_public_key.verify(
        server_certificate.signature,
        server_certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        server_certificate.signature_hash_algorithm,
    )
    print("✓ Server certificate verified")

    # Phase 2: Diffie-Hellman key exchange
    dh_params_data = test_socket.recv(65536)
    dh_params = json.loads(dh_params_data.decode())
    
    prime_p = int(dh_params["p"])
    generator_g = int(dh_params["g"])
    server_public_bytes = base64.b64decode(dh_params["server_pub"])
    server_public_int = int.from_bytes(server_public_bytes, "big")

    # Generate client DH key pair
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
    test_socket.send(json.dumps(client_dh_message).encode())

    # Compute shared secret and session key
    server_public_numbers = dh.DHPublicNumbers(
        server_public_int,
        dh_parameters.parameter_numbers()
    )
    server_public_key = server_public_numbers.public_key(backend=default_backend())
    
    shared_secret = client_dh_private.exchange(server_public_key)
    session_key = derive_session_key(shared_secret)

    # Phase 3: Authentication
    auth_payload = {
        "type": "login",
        "email": test_config.email,
        "password": test_config.password,
    }
    auth_payload_bytes = json.dumps(auth_payload).encode()
    encrypted_auth = encrypt_message(session_key, auth_payload_bytes)
    
    auth_message = {
        "type": "auth",
        "ct": base64.b64encode(encrypted_auth).decode()
    }
    test_socket.send(json.dumps(auth_message).encode())

    auth_response_data = test_socket.recv(65536)
    auth_response = json.loads(auth_response_data.decode())
    print(f"Authentication response: {auth_response.get('type')}")
    
    if auth_response.get("type") != "auth_resp":
        print("Authentication failed, exiting test")
        test_socket.close()
        return

    # Phase 4: Prepare test message for replay attack
    client_private_key = serialization.load_pem_private_key(
        Path(test_config.client_key).read_bytes(),
        password=None,
        backend=default_backend()
    )

    message_sequence = 1
    message_timestamp = int(time.time() * 1000)
    message_plaintext = b"Replay attack test message (sequence=1)"

    # Encrypt message
    message_ciphertext = encrypt_message(session_key, message_plaintext)
    
    # Compute hash and sign
    hash_input = (str(message_sequence) + str(message_timestamp)).encode() + message_ciphertext
    message_hash = hashlib.sha256(hash_input).digest()
    message_signature = client_private_key.sign(
        message_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Construct message
    test_message = {
        "type": "msg",
        "seqno": message_sequence,
        "ts": message_timestamp,
        "ct": base64.b64encode(message_ciphertext).decode(),
        "sig": base64.b64encode(message_signature).decode(),
    }

    # Send first message (should be accepted)
    test_socket.send(json.dumps(test_message).encode())
    print(f"✓ Sent first message with seqno={message_sequence} (should be accepted)")

    # Wait a moment for server to process
    time.sleep(0.5)

    # Send same message again (replay attack - should be rejected)
    test_socket.send(json.dumps(test_message).encode())
    print(f"⚠ Sent replayed message with same seqno={message_sequence} (should be rejected)")

    # Wait for server response or connection close
    time.sleep(1)
    
    try:
        response = test_socket.recv(4096)
        if response:
            print(f"Server response: {response.decode(errors='ignore')}")
    except:
        pass

    test_socket.close()
    print("\n✓ TEST COMPLETED")
    print("Expected: Server should log 'REPLAY or OUT-OF-ORDER detected' for second message")


if __name__ == "__main__":
    main()
