import logging
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from api.utils import encrypt, decrypt, get_instance_public_ip
from api.models.user import User
from api.models.user_containers import UserContainers
from api.models.ec2_instances import EC2Instances
from api.models.ec2_key_pair import EC2KeyPair
from api.models.aws_credentials import AwsCredentials
from api.services.ec2_service import InstanceSetUp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

aws_credentials_bp = Blueprint('aws_credentials_bp', __name__)

@aws_credentials_bp.route('/aws/credentials', methods=['POST'])
@jwt_required()
def store_aws_credentials():
    data = request.get_json()
    aws_access_key_id = data.get('aws_access_key_id')
    aws_secret_access_key = data.get('aws_secret_access_key')
    preferred_aws_region = data.get('preferred_aws_region')

    current_user = get_jwt_identity()

    user = User.get_or_none(username=current_user)
    if not user:
        return jsonify({'message': f'User {current_user} not found'}), 404

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
    current_user = get_jwt_identity()
    data = request.get_json()

    # Fetch the user from the database
    user = User.get_or_none(username=current_user)
    if not user:
        return jsonify({'message': f'User {current_user} not found'}), 404

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
        username=current_user,
        container_name=container_name,
        requested_cpu=requested_cpu,
        requested_storage=requested_storage,
        aws_secret_key=aws_secret_access_key,
        aws_access_key=aws_access_key_id,
        aws_region=preferred_aws_region
    )

    # Create the EC2 instance
    try:
        instance_id, public_ip = instance_setup.create_ec2_instance()
        logger.info(f"EC2 instance created with ID: {instance_id} and Public IP: {public_ip}")

        # Add container information to UserContainers table
        ec2_instance = EC2Instances.get(EC2Instances.ec2_instance_id == instance_id)
        UserContainers.create(
            user=user,
            container_name=container_name,
            ec2_instance=ec2_instance
        )
        logger.info(f"Container {container_name} associated with EC2 instance {instance_id} successfully.")

        return jsonify({'message': 'EC2 instance created successfully', 'instance_id': instance_id, 'public_ip': public_ip}), 200
    
    except Exception as e:
        logger.error(f"Failed to create EC2 instance: {e}")
        return jsonify({'message': 'Failed to create EC2 instance', 'error': str(e)}), 500


@aws_credentials_bp.route('/aws/container_connect', methods=['POST'])
@jwt_required()
def ssh_container():
    logger.info("Received request to connect to container.")
    current_user = get_jwt_identity()
    logger.info(f"Current user: {current_user}")

    data = request.get_json()
    logger.info(f"Received data: {data}")

    if not data or 'container_name' not in data:
        logger.error("No container_name provided in request.")
        return jsonify({'message': 'container_name is required'}), 400

    container_name = data.get('container_name')

    # Fetch the user from the database
    user = User.get_or_none(User.username == current_user)
    if not user:
        logger.error(f"User {current_user} not found.")
        return jsonify({'message': f'User {current_user} not found'}), 404

    # Fetch the AWS credentials for the user from the database
    aws_credentials = AwsCredentials.get_or_none(AwsCredentials.user == user)
    if not aws_credentials:
        logger.error(f"AWS credentials not found for user {current_user}.")
        return jsonify({'message': 'AWS credentials not found for the user'}), 404

    # Decrypt the credentials
    aws_access_key_id = decrypt(aws_credentials.aws_access_key_id)
    aws_secret_access_key = decrypt(aws_credentials.aws_secret_access_key)
    preferred_aws_region = aws_credentials.preferred_aws_region

    try:
        container = UserContainers.get((UserContainers.user == user) & (UserContainers.container_name == container_name))
        instance_id = container.ec2_instance.ec2_instance_id
        logger.info(f"Found instance ID: {instance_id}")
    except UserContainers.DoesNotExist:
        logger.error(f"Instance with container name {container_name} not found.")
        return jsonify({"error": "Instance not found"}), 404

    # Fetch the public IP dynamically
    public_ip = get_instance_public_ip(aws_access_key_id, aws_secret_access_key, preferred_aws_region, instance_id)
    if not public_ip:
        logger.error(f"Unable to fetch public IP for instance {instance_id}.")
        return jsonify({"error": "Unable to fetch public IP for instance"}), 500

    # Download key pair
    instance = EC2Instances.get((EC2Instances.user == user) & (EC2Instances.ec2_instance_id == instance_id))
    key_pair = EC2KeyPair.get(EC2KeyPair.key_pair == instance.key_file.key_pair)
    s3_file_path = key_pair.s3_file_path

    logger.info(f"Returning instance public IP and key pair S3 path")

    return jsonify({
        "public_ip": public_ip,
        "s3_file_path": s3_file_path,
        "aws_access_key_id": aws_access_key_id,
        "aws_secret_access_key": aws_secret_access_key,
        "preferred_aws_region": preferred_aws_region
    }), 200


# Add container creation and database integration
# Encrypt key pair and where to save
# Save resources ids in DB to clean up if needed
# Add container deletion
# Add ssh to the s3 bucket
