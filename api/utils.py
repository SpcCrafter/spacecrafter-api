import os
import logging
import subprocess
import boto3
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
from flask_jwt_extended import get_jwt_identity
from api.aws import get_ssm_parameter
from api.models.user import User
from api.models.aws_credentials import AwsCredentials
from api.models.ec2_instances import EC2Instances
from api.models.ec2_key_pair import EC2KeyPair

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


def get_instance_id(username, container_name):
    user = User.get(User.username == username)
    instance = EC2Instances.get(
        (EC2Instances.user == user) & 
        (EC2Instances.ec2_instance_id.contains(container_name))
    )
    return instance.ec2_instance_id


def get_key_pair(username, container_name):
    user = User.get(User.username == username)
    key_pair = EC2KeyPair.get(
        (EC2KeyPair.user == user) &
        (EC2KeyPair.key_pair.contains(container_name))
    )
    return key_pair.s3_file_path


def download_key_pair(s3_file_path, local_key_path, aws_access_key, aws_secret_key, region):
    bucket_name, key_name = s3_file_path.replace("s3://", "").split("/", 1)

        # Create a session with the decrypted credentials
    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region
    )
    s3 = session.client('s3')
    kms = session.client('kms')

    try:
        encrypted_key = s3.get_object(Bucket=bucket_name, Key=key_name)['Body'].read()
        decrypted_key = kms.decrypt(CiphertextBlob=encrypted_key)['Plaintext']
        with open(local_key_path, 'wb') as key_file:
            key_file.write(decrypted_key)
        os.chmod(local_key_path, 0o400) 
        logger.info(f"Downloaded key pair to {local_key_path}")
    except ClientError as e:
        logger.error(f"Failed to download key pair from S3: {e}")
        raise e


def ssh_into_instance(public_ip, key_path, user='ubuntu'):
    ssh_command = f"ssh -i {key_path} {user}@{public_ip}"
    subprocess.run(ssh_command, shell=True)


def get_instance_public_ip(aws_access_key, aws_secret_key, region, instance_id):
    try:
        ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        reservations = ec2_client.describe_instances(InstanceIds=[instance_id]).get("Reservations")
        for reservation in reservations:
            for instance in reservation.get("Instances"):
                return instance.get("PublicIpAddress")
    except ClientError as e:
        logger.error(f"Failed to get public IP for instance {instance_id}: {e}")
        raise