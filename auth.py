"""
Password Authentication Utilities
Provides secure password hashing and verification functions using
SHA-256 with per-user random salts for protection against rainbow table attacks.
"""
import hashlib
import hmac
import secrets


def create_random_salt(salt_length: int = 16) -> bytes:
    """
    Generate a cryptographically secure random salt.
    
    Args:
        salt_length: Number of bytes for the salt (default: 16)
    
    Returns:
        Random bytes suitable for password hashing
    """
    return secrets.token_bytes(salt_length)


def compute_password_hash(password: str, salt: bytes) -> str:
    """
    Compute a salted SHA-256 hash of a password.
    Format: hex(SHA256(salt || password))
    
    Args:
        password: Plaintext password string (UTF-8 encoded)
        salt: Random salt bytes
    
    Returns:
        Hexadecimal string representation of the hash (64 characters)
    """
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = password
    
    hash_digest = hashlib.sha256(salt + password_bytes).hexdigest()
    return hash_digest


def check_password_match(stored_salt: bytes, stored_hash: str, candidate_password: str) -> bool:
    """
    Verify a candidate password against a stored hash using constant-time comparison.
    This prevents timing attacks that could reveal information about the password.
    
    Args:
        stored_salt: The salt used when the password was originally hashed
        stored_hash: The stored password hash (hex string)
        candidate_password: The password to verify
    
    Returns:
        True if the password matches, False otherwise
    """
    candidate_hash = compute_password_hash(candidate_password, stored_salt)
    return hmac.compare_digest(stored_hash, candidate_hash)
