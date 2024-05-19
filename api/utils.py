import os
import logging
from cryptography.fernet import Fernet
from flask_jwt_extended import get_jwt_identity
from api.aws import get_ssm_parameter
from api.models.user import User
from api.models.aws_credentials import AwsCredentials

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

def get_aws_credentials(current_user_id):
    current_user_id = get_jwt_identity()

    user = User.get_or_none(username=current_user_id)
    if not user:
        raise Exception(f'User not found')

    aws_credentials = AwsCredentials.get_or_none(user=user)
    if not aws_credentials:
        raise Exception('AWS Credentials not found')

    decrypted_access_key = decrypt(aws_credentials.aws_access_key_id)
    decrypted_secret_key = decrypt(aws_credentials.aws_secret_access_key)

    return decrypted_access_key, decrypted_secret_key
