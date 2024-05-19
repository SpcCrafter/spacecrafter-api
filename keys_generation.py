# Grab it and safe in SSM
import secrets
from cryptography.fernet import Fernet

secret_key = secrets.token_urlsafe(32)
print("JWT secret key: " + secret_key)

def generate_encryption_key():
    return Fernet.generate_key()

print("Encryption key for a password encryption: " + generate_encryption_key())
