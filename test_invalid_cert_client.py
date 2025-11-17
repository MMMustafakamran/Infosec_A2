#!/usr/bin/env python3
"""
Invalid Certificate Test Client
Tests server's ability to reject certificates not signed by the trusted CA.
This demonstrates proper certificate validation and security enforcement.

Expected Behavior:
- Server should detect invalid certificate
- Server should log verification failure
- Server should send "BAD CERT" error or close connection
- Connection should be terminated
"""
import socket
import json
import base64
import argparse
import secrets
from pathlib import Path


def read_certificate_file(filepath):
    """Read a PEM certificate file from disk."""
    return Path(filepath).read_bytes()


def main():
    """Main test execution function."""
    argument_parser = argparse.ArgumentParser(
        description="Test client with invalid certificate to verify server validation"
    )
    argument_parser.add_argument("--host", default="127.0.0.1", help="Server hostname")
    argument_parser.add_argument("--port", type=int, default=9000, help="Server port")
    argument_parser.add_argument(
        "--bad-client-cert",
        default="certs_bad/badclient.example.cert.pem",
        help="Path to invalid/self-signed certificate file"
    )
    test_config = argument_parser.parse_args()

    # Establish TCP connection to server
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        test_socket.connect((test_config.host, test_config.port))
        print(f"Connected to server at {test_config.host}:{test_config.port}")
    except ConnectionRefusedError:
        print(f"Error: Could not connect to {test_config.host}:{test_config.port}")
        return

    # Load invalid certificate (not signed by trusted CA)
    invalid_certificate_pem = read_certificate_file(test_config.bad_client_cert)
    client_nonce = secrets.token_bytes(16)

    # Construct hello message with invalid certificate
    client_hello_message = {
        "type": "hello",
        "client_cert": base64.b64encode(invalid_certificate_pem).decode(),
        "nonce": base64.b64encode(client_nonce).decode(),
    }

    # Send hello message with invalid certificate
    test_socket.send(json.dumps(client_hello_message).encode())
    print("Sent hello message with invalid certificate")

    # Wait for server response
    # Server should either send error JSON or close connection immediately
    try:
        server_response = test_socket.recv(4096)
        if server_response:
            try:
                response_json = json.loads(server_response.decode())
                print(f"Server response: {response_json}")
                if response_json.get("error") == "BAD CERT":
                    print("✓ TEST PASSED: Server correctly rejected invalid certificate")
                else:
                    print(f"⚠ Server responded but with unexpected format: {response_json}")
            except json.JSONDecodeError:
                print(f"Server response (non-JSON): {server_response.decode(errors='ignore')}")
        else:
            print("✓ TEST PASSED: Server closed connection (expected behavior for invalid cert)")
    except socket.error as socket_error:
        print(f"Connection error (expected if server closes): {socket_error}")
    except Exception as unexpected_error:
        print(f"Unexpected error: {unexpected_error}")

    test_socket.close()
    print("Test completed")


if __name__ == "__main__":
    main()
