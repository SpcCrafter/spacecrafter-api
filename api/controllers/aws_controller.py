from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from api.utils import encrypt, decrypt
from api.models.user import User
from api.models.aws_credentials import AwsCredentials
from api.services.ec2_service import InstanceSetUp

aws_credentials_bp = Blueprint('aws_credentials_bp', __name__)

@aws_credentials_bp.route('/aws/credentials', methods=['POST'])
@jwt_required()
def store_aws_credentials():
    data = request.get_json()
    aws_access_key_id = data.get('aws_access_key_id')
    aws_secret_access_key = data.get('aws_secret_access_key')
    preferred_aws_region = data.get('preferred_aws_region')

    current_user_id = get_jwt_identity()

    user = User.get_or_none(username=current_user_id)
    if not user:
        return jsonify({'message': f'User {current_user_id} not found'}), 404

    encrypted_access_key = encrypt(aws_access_key_id)
    encrypted_secret_key = encrypt(aws_secret_access_key)

    AwsCredentials.create(
        user=user,
        aws_access_key_id=encrypted_access_key,
        aws_secret_access_key=encrypted_secret_key,
        preferred_aws_region=preferred_aws_region
    )

    return jsonify({'message': 'AWS Credentials stored successfully'}), 201


@aws_credentials_bp.route('/aws/create_container', methods=['POST'])
@jwt_required()
def create_container():
    current_user_id = get_jwt_identity()
    data = request.get_json()

    # Fetch the user from the database
    user = User.get_or_none(username=current_user_id)
    if not user:
        return jsonify({'message': f'User {current_user_id} not found'}), 404

    # Fetch the AWS credentials for the user from the database
    aws_credentials = AwsCredentials.get_or_none(user=user)
    if not aws_credentials:
        return jsonify({'message': 'AWS credentials not found for the user'}), 404

    # Decrypt the credentials
    aws_access_key_id = decrypt(aws_credentials.aws_access_key_id)
    aws_secret_access_key = decrypt(aws_credentials.aws_secret_access_key)
    preferred_aws_region = aws_credentials.preferred_aws_region

    # Extract other required parameters from the data
    container_name = data.get('container_name')
    requested_cpu = data.get('cpu')
    requested_storage = data.get('storage')

    # Initialize the InstanceSetUp class
    instance_setup = InstanceSetUp(
        user_id=current_user_id,
        container_name=container_name,
        requested_cpu=requested_cpu,
        requested_storage=requested_storage,
        aws_secret_key=aws_secret_access_key,
        aws_access_key=aws_access_key_id,
        aws_region=preferred_aws_region
    )

    # Create the EC2 instance
    try:
        instance_id = instance_setup.create_ec2_instance()
        return jsonify({'message': 'EC2 instance created successfully', 'instance_id': instance_id}), 200
    except Exception as e:
        return jsonify({'message': 'Failed to create EC2 instance', 'error': str(e)}), 500

# Add container creation and database integration
# Encrypt key pair and where to save
# Save resources ids in DB to clean up if needed
# Add container deletion
# Add ssh to the s3 bucket
