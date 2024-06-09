import time
import logging
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from api.utils import encrypt, decrypt, get_instance_public_ip, download_key_pair
from api.models.user import User
from api.models.user_containers import UserContainers
from api.models.ec2_instances import EC2Instances
from api.models.ec2_key_pair import EC2KeyPair
from api.models.aws_credentials import AwsCredentials
from api.services.ec2_service import InstanceSetUp, InstanceCleanUp
from api.services.container_service import ContainerService

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

    user = User.get_or_none(username=current_user)
    if not user:
        return jsonify({'message': f'User {current_user} not found'}), 404

    aws_credentials = AwsCredentials.get_or_none(user=user)
    if not aws_credentials:
        return jsonify({'message': 'AWS credentials not found for the user'}), 404

    container_name = data.get('container_name')

    # Check if a container with the same name already exists for the user
    existing_container = UserContainers.get_or_none(
        (UserContainers.user == user) &
        (UserContainers.container_name == container_name)
    )
    if existing_container:
        logger.info(f'Container with name {container_name} already exists')
        return jsonify({'message': f'Container with name {container_name} already exists'}), 400

    aws_access_key_id = decrypt(aws_credentials.aws_access_key_id)
    aws_secret_access_key = decrypt(aws_credentials.aws_secret_access_key)
    preferred_aws_region = aws_credentials.preferred_aws_region

    requested_cpu = data.get('cpu')
    requested_storage = data.get('storage')
    container_params = {
        'container_name': container_name,
        'image': data.get('image'),
        'env_vars': data.get('env_vars', {})
    }

    instance_setup = InstanceSetUp(
        username=current_user,
        container_name=container_name,
        requested_cpu=requested_cpu,
        requested_storage=requested_storage,
        aws_secret_key=aws_secret_access_key,
        aws_access_key=aws_access_key_id,
        aws_region=preferred_aws_region
    )

    container_service = ContainerService(aws_access_key_id,
                                         aws_secret_access_key,
                                         preferred_aws_region)

    try:
        instance_id, public_ip = instance_setup.create_ec2_instance()
        logger.info(f"EC2 instance created with ID: {instance_id} and Public IP: {public_ip}")

        ec2_instance = EC2Instances.get(EC2Instances.ec2_instance_id == instance_id)
        UserContainers.create(
            user=user,
            container_name=container_name,
            ec2_instance=ec2_instance
        )
        logger.info(f"Container {container_name} associated with EC2 instance {instance_id} successfully.")

        time.sleep(120)

        key_pair = EC2KeyPair.get(EC2KeyPair.id == ec2_instance.key_file)
        s3_file_path = key_pair.s3_file_path
        local_key_path = "/tmp/temp_key.pem"

        download_key_pair(s3_file_path, local_key_path,
                          aws_access_key_id, aws_secret_access_key, preferred_aws_region)
        logger.info(f"Downloaded key pair to {local_key_path}")

        container_service.ssh_and_create_container(public_ip, local_key_path, container_params)
        logger.info(f"Container {container_name} created successfully on instance {instance_id}.")

        return jsonify({'message': 'EC2 instance and container created successfully', 
                        'instance_id': instance_id, 
                        'public_ip': public_ip}), 200

    except Exception as e:
        logger.error(f"Failed to create container on instance: {e}")
        return jsonify({'message': 'Failed to create container on instance', 'error': str(e)}), 500


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

    user = User.get_or_none(User.username == current_user)
    if not user:
        logger.error(f"User {current_user} not found.")
        return jsonify({'message': f'User {current_user} not found'}), 404

    aws_credentials = AwsCredentials.get_or_none(AwsCredentials.user == user)
    if not aws_credentials:
        logger.error(f"AWS credentials not found for user {current_user}.")
        return jsonify({'message': 'AWS credentials not found for the user'}), 404

    aws_access_key_id = decrypt(aws_credentials.aws_access_key_id)
    aws_secret_access_key = decrypt(aws_credentials.aws_secret_access_key)
    preferred_aws_region = aws_credentials.preferred_aws_region

    try:
        container = UserContainers.get((UserContainers.user == user) &
                                       (UserContainers.container_name == container_name))
        instance_id = container.ec2_instance.ec2_instance_id
        logger.info(f"Found instance ID: {instance_id}")
    except UserContainers.DoesNotExist:
        logger.error(f"Instance with container name {container_name} not found.")
        return jsonify({"message": "Instance not found"}), 404

    public_ip = get_instance_public_ip(aws_access_key_id, aws_secret_access_key,
                                       preferred_aws_region, instance_id)
    if not public_ip:
        logger.error(f"Unable to fetch public IP for instance {instance_id}.")
        return jsonify({"message": "Unable to fetch public IP for instance"}), 500

    instance = EC2Instances.get((EC2Instances.user == user) &
                                (EC2Instances.ec2_instance_id == instance_id))
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


@aws_credentials_bp.route('/aws/delete_container', methods=['DELETE'])
@jwt_required()
def delete_container():
    current_user = get_jwt_identity()
    data = request.get_json()

    container_name = data.get('container_name')

    user = User.get_or_none(User.username == current_user)
    if not user:
        return jsonify({'message': f'User {current_user} not found'}), 404

    aws_credentials = AwsCredentials.get_or_none(AwsCredentials.user == user)
    if not aws_credentials:
        return jsonify({'message': 'AWS credentials not found for the user'}), 404

    aws_access_key_id = decrypt(aws_credentials.aws_access_key_id)
    aws_secret_access_key = decrypt(aws_credentials.aws_secret_access_key)
    preferred_aws_region = aws_credentials.preferred_aws_region

    try:
        container = UserContainers.get((UserContainers.user == user) &
                                       (UserContainers.container_name == container_name))
        instance_id = container.ec2_instance.ec2_instance_id
        logger.info(f"Found instance ID: {instance_id}")
    except UserContainers.DoesNotExist:
        logger.error(f"Instance with container name {container_name} not found.")
        return jsonify({"message": "Instance not found"}), 404

    public_ip = get_instance_public_ip(aws_access_key_id, aws_secret_access_key,
                                       preferred_aws_region, instance_id)
    if not public_ip:
        logger.error(f"Unable to fetch public IP for instance {instance_id}.")
        return jsonify({"message": "Unable to fetch public IP for instance"}), 500

    instance_cleanup = InstanceCleanUp(aws_access_key_id,
                                       aws_secret_access_key,
                                       preferred_aws_region)
    container_service = ContainerService(aws_access_key_id,
                                         aws_secret_access_key,
                                         preferred_aws_region)

    try:
        instance = EC2Instances.get(EC2Instances.ec2_instance_id == instance_id)
        key_pair = EC2KeyPair.get(EC2KeyPair.key_pair == instance.key_file.key_pair)
        local_key_path = "/tmp/temp_key.pem"
        
        download_key_pair(key_pair.s3_file_path, local_key_path,
                          aws_access_key_id, aws_secret_access_key, preferred_aws_region)
        logger.info(f"Downloaded key pair to {local_key_path}")

        container_service.remove_container(public_ip, local_key_path, container_name)
        logger.info(f"Container {container_name} removed successfully from instance {instance_id}.")

        instance_cleanup.terminate_ec2_instance(instance_id)
        logger.info(f"EC2 instance {instance_id} terminated successfully.")

        instance_cleanup.delete_key_pair(instance.key_file.key_pair)
        logger.info(f"Key pair {instance.key_file.key_pair} deleted successfully.")

        instance_cleanup.delete_security_group(instance.security_group.security_group_id)
        logger.info(f"Security group {instance.security_group.security_group_id} deleted successfully.")

        UserContainers.delete().where(UserContainers.container_name == container_name).execute()
        EC2Instances.delete().where(EC2Instances.ec2_instance_id == instance_id).execute()

        return jsonify({'message': 'Container and related resources deleted successfully'}), 200

    except Exception as e:
        logger.error(f"Failed to delete container and related resources: {e}")
        return jsonify({'message': 'Failed to delete container and related resources', 'error': str(e)}), 500
