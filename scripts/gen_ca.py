#!/usr/bin/env python3
"""
Root Certificate Authority Generator
Creates a self-signed root CA certificate and private key for issuing
client and server certificates in the secure chat system.

Usage:
    python3 gen_ca.py --outdir certs --cn "SecureChat Root CA"

Output:
    certs/ca.key.pem  - CA private key (DO NOT COMMIT TO GIT)
    certs/ca.cert.pem - CA self-signed certificate

Security Note:
    Keep the private key secure and never commit it to version control.
"""
import argparse
import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_root_ca(output_directory, common_name, validity_days):
    """
    Generate a root CA private key and self-signed certificate.
    
    Args:
        output_directory: Directory to write certificate files
        common_name: Common name for the CA certificate
        validity_days: Number of days the certificate is valid
    """
    # Generate RSA private key (4096 bits, public exponent 65537)
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    
    # Create certificate subject and issuer (same for self-signed CA)
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
    
    current_time = datetime.datetime.utcnow()
    
    # Build and sign the certificate
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)  # Self-signed
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current_time)
        .not_valid_after(current_time + datetime.timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
    )
    
    # Ensure output directory exists
    os.makedirs(output_directory, exist_ok=True)
    
    # Write private key to file
    key_file_path = os.path.join(output_directory, 'ca.key.pem')
    with open(key_file_path, 'wb') as key_file:
        key_file.write(
            ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Write certificate to file
    cert_file_path = os.path.join(output_directory, 'ca.cert.pem')
    with open(cert_file_path, 'wb') as cert_file:
        cert_file.write(
            ca_certificate.public_bytes(serialization.Encoding.PEM)
        )
    
    print(f"Root CA private key written to: {key_file_path}")
    print(f"Root CA certificate written to: {cert_file_path}")
    print(f"Certificate valid for {validity_days} days")
    print("WARNING: Keep the private key secure and do not commit it to git!")


def main():
    """Main entry point for CA generation script."""
    parser = argparse.ArgumentParser(
        description="Generate a root Certificate Authority for secure chat"
    )
    parser.add_argument(
        '--outdir',
        default='certs',
        help='Output directory for certificate files (default: certs)'
    )
    parser.add_argument(
        '--cn',
        default='SecureChat Root CA',
        help='Common name for the CA certificate (default: SecureChat Root CA)'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=3650,
        help='Certificate validity period in days (default: 3650)'
    )
    
    args = parser.parse_args()
    generate_root_ca(args.outdir, args.cn, args.days)


if __name__ == '__main__':
    main()
