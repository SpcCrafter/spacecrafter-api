from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from api.database import database
from api.utils import encrypt, decrypt, get_encryption_key
from api.models.user import User
from api.models.aws_credentials import AwsCredentials

aws_credentials_bp = Blueprint('aws_credentials_bp', __name__)

@aws_credentials_bp.route('/aws/credentials', methods=['POST'])
@jwt_required()
def store_aws_credentials():
    data = request.get_json()
    aws_access_key_id = data.get('aws_access_key_id')
    aws_secret_access_key = data.get('aws_secret_access_key')

    current_user_id = get_jwt_identity()

    user = User.get_or_none(username=current_user_id)
    if not user:
        return jsonify({'message': f'User {current_user_id} not found'}), 404

    encrypted_access_key = encrypt(aws_access_key_id)
    encrypted_secret_key = encrypt(aws_secret_access_key)

    AwsCredentials.create(
        user=user,
        aws_access_key_id=encrypted_access_key,
        aws_secret_access_key=encrypted_secret_key
    )

    return jsonify({'message': 'AWS Credentials stored successfully'}), 201

def get_aws_credentials():
    current_user_id = get_jwt_identity()

    user = User.get_or_none(username=current_user_id)
    if not user:
        return jsonify({'message': f'User {current_user_id} not found'}), 404

    aws_credentials = AwsCredentials.get_or_none(user=user)
    if not aws_credentials:
        return jsonify({'message': 'AWS Credentials not found'}), 404

    decrypted_access_key = decrypt(aws_credentials.aws_access_key_id)
    decrypted_secret_key = decrypt(aws_credentials.aws_secret_access_key)

    return decrypted_access_key, decrypted_secret_key
