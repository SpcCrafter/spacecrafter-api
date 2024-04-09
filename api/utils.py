import os
import logging
from cryptography.fernet import Fernet
from api.aws import get_ssm_parameter

logger = logging.getLogger(__name__)

def get_encryption_key():
    try:
        env = os.environ.get('FLASK_ENV')
        if env == 'prod':
            encryption_key = get_ssm_parameter('/api/encryption_key')
        elif env == 'dev':
            encryption_key = os.getenv('ENCRYPTION_KEY')
        return encryption_key.encode('utf-8')  # Encode the key as bytes
    except KeyError as e:
        logger.error(f"Failed to retrieve encryption key: {e}")
        raise

def encrypt(plain_text):
    encryption_key = get_encryption_key()
    cipher_suite = Fernet(encryption_key)
    encrypted_text = cipher_suite.encrypt(plain_text.encode('utf-8'))
    return encrypted_text.decode('utf-8')

def decrypt(encrypted_text):
    encryption_key = get_encryption_key()
    cipher_suite = Fernet(encryption_key)
    decrypted_text = cipher_suite.decrypt(encrypted_text.encode('utf-8'))
    return decrypted_text.decode('utf-8')
