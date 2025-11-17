#!/usr/bin/env python3
"""
Certificate Generation Script
Generates RSA key pairs and X.509 certificates signed by a root CA
for use in the secure chat system (server or client certificates).

Usage:
    Server certificate:
        python3 gen_cert.py --ca-key certs/ca.key.pem --ca-cert certs/ca.cert.pem \\
            --cn server.example --outdir certs --type server
    
    Client certificate:
        python3 gen_cert.py --ca-key certs/ca.key.pem --ca-cert certs/ca.cert.pem \\
            --cn client.example --outdir certs --type client

Output:
    certs/<cn>.key.pem  - Private key (DO NOT COMMIT TO GIT)
    certs/<cn>.cert.pem - Signed certificate

Security Note:
    Keep all private keys secure and never commit them to version control.
"""
import argparse
import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def load_private_key_from_file(key_file_path):
    """
    Load a PEM-encoded private key from a file.
    
    Args:
        key_file_path: Path to the private key file
    
    Returns:
        Private key object
    """
    with open(key_file_path, 'rb') as key_file:
        key_data = key_file.read()
        return serialization.load_pem_private_key(
            key_data,
            password=None,
            backend=default_backend()
        )


def load_certificate_from_file(cert_file_path):
    """
    Load a PEM-encoded X.509 certificate from a file.
    
    Args:
        cert_file_path: Path to the certificate file
    
    Returns:
        Certificate object
    """
    with open(cert_file_path, 'rb') as cert_file:
        cert_data = cert_file.read()
        return x509.load_pem_x509_certificate(
            cert_data,
            backend=default_backend()
        )


def generate_signed_certificate(
    ca_key_path,
    ca_cert_path,
    common_name,
    output_directory,
    certificate_type,
    validity_days
):
    """
    Generate a new RSA key pair and certificate signed by the CA.
    
    Args:
        ca_key_path: Path to CA private key file
        ca_cert_path: Path to CA certificate file
        common_name: Common name for the new certificate
        output_directory: Directory to write certificate files
        certificate_type: 'server' or 'client'
        validity_days: Number of days the certificate is valid
    """
    # Load CA key and certificate
    ca_private_key = load_private_key_from_file(ca_key_path)
    ca_certificate = load_certificate_from_file(ca_cert_path)
    
    # Generate new RSA key pair (3072 bits)
    entity_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
        backend=default_backend()
    )
    
    # Create certificate subject name
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
    
    current_time = datetime.datetime.utcnow()
    
    # Build certificate
    certificate_builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(ca_certificate.subject)  # Issued by CA
        .public_key(entity_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current_time)
        .not_valid_after(current_time + datetime.timedelta(days=validity_days))
    )
    
    # Add basic constraints (end-entity, not a CA)
    certificate_builder = certificate_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    
    # Add extended key usage based on certificate type
    if certificate_type == 'server':
        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        )
    else:  # client
        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )
    
    # Sign certificate with CA private key
    signed_certificate = certificate_builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    # Ensure output directory exists
    os.makedirs(output_directory, exist_ok=True)
    
    # Write private key to file
    key_file_path = os.path.join(output_directory, f'{common_name}.key.pem')
    with open(key_file_path, 'wb') as key_file:
        key_file.write(
            entity_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Write certificate to file
    cert_file_path = os.path.join(output_directory, f'{common_name}.cert.pem')
    with open(cert_file_path, 'wb') as cert_file:
        cert_file.write(
            signed_certificate.public_bytes(serialization.Encoding.PEM)
        )
    
    print(f"Private key written to: {key_file_path}")
    print(f"Certificate written to: {cert_file_path}")
    print(f"Certificate type: {certificate_type}")
    print(f"Certificate valid for {validity_days} days")
    print("WARNING: Keep the private key secure and do not commit it to git!")


def main():
    """Main entry point for certificate generation script."""
    parser = argparse.ArgumentParser(
        description="Generate X.509 certificates signed by a root CA"
    )
    parser.add_argument(
        '--ca-key',
        required=True,
        help='Path to CA private key file'
    )
    parser.add_argument(
        '--ca-cert',
        required=True,
        help='Path to CA certificate file'
    )
    parser.add_argument(
        '--cn',
        required=True,
        help='Common name for the certificate (e.g., server.example)'
    )
    parser.add_argument(
        '--outdir',
        default='certs',
        help='Output directory for certificate files (default: certs)'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=825,
        help='Certificate validity period in days (default: 825)'
    )
    parser.add_argument(
        '--type',
        choices=['server', 'client'],
        default='server',
        help='Certificate type: server or client (default: server)'
    )
    
    args = parser.parse_args()
    generate_signed_certificate(
        args.ca_key,
        args.ca_cert,
        args.cn,
        args.outdir,
        args.type,
        args.days
    )


if __name__ == '__main__':
    main()
