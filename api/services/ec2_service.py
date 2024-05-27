import logging
import math
import boto3
from botocore.exceptions import ClientError
from api.models.user import User
from api.models.ec2_key_pair import EC2KeyPair
from api.models.aws_security_groups import SecurityGroups
from api.models.ec2_instances import EC2Instances
from api.models.kms_keys import KMSKeys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# logger = logging.getLogger('peewee')
# logger.setLevel(logging.DEBUG)
# logger.addHandler(logging.StreamHandler())


INSTANCE_TYPE_MAPPING = [
    {'name': 't2.micro', 'cpu': 1, 'memory': 1},
    {'name': 't2.small', 'cpu': 1, 'memory': 2},
    {'name': 't2.medium', 'cpu': 2, 'memory': 4},
    {'name': 't3.large', 'cpu': 2, 'memory': 8},
]

# Scaling factor to ensure the instance has more resources than the minimum requested.
SCALING_FACTOR = 1.5

# EBS Volume size requirements
OS_AND_DEPENDENCIES_SIZE_GB = 8
MINIMUM_EBS_SIZE_GB = 10

class InstanceSetUp():
    def __init__(self, username, container_name,
                 requested_cpu, requested_storage,
                 aws_secret_key, aws_access_key, aws_region=None):
        self.username = username
        self.container_name = container_name
        self.requested_storage = requested_storage
        self.requested_cpu = requested_cpu
        self.aws_secret_key = aws_secret_key
        self.aws_access_key = aws_access_key
        self.aws_region = aws_region

        logger.info(f"Initialized InstanceSetUp with username: {username}, container_name: {container_name}, requested_cpu: {requested_cpu}, requested_storage: {requested_storage}")

    def setup_boto_session(self):
        session = boto3.Session(
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key,
            region_name=self.aws_region
        )
        return session

    def find_best_instance_type(self):
        # Apply the scaling factor to the user's request.
        required_cpu = self.requested_cpu * SCALING_FACTOR
        
        # Round up to nearest whole number to handle fractional CPU requests
        required_cpu = math.ceil(required_cpu)

        best_match = None

        # Iterate through the instance types to find the best match.
        for instance_type in INSTANCE_TYPE_MAPPING:
            if instance_type['cpu'] >= required_cpu:
                if best_match is None or instance_type['cpu'] < best_match['cpu']:
                    best_match = instance_type

        # Return the name of the best matching instance type or None if no match is found.
        return best_match['name'] if best_match else None

    def calculate_ebs_volume_size(self, requested_storage: int):
        total_required_size_gb = OS_AND_DEPENDENCIES_SIZE_GB + requested_storage
        ebs_volume_size_gb = max(total_required_size_gb, MINIMUM_EBS_SIZE_GB)
        return ebs_volume_size_gb

    def create_kms_key(self):
        username = self.username.replace('_', '-')
        session = self.setup_boto_session()
        kms_client = session.client('kms')

        alias_name = f"alias/{username}-key"

        # Check if the key alias already exists
        try:
            response = kms_client.describe_key(KeyId=alias_name)
            key_id = response['KeyMetadata']['KeyId']
            logger.info(f"Found existing KMS key with ID: {key_id} for user {self.username}")

            user = User.get(User.username == self.username)
            KMSKeys.create(
                user=user,
                key_alias=alias_name,
                key_id=key_id)

            return key_id
        except kms_client.exceptions.NotFoundException:
            logger.info(f"No existing KMS key found for alias: {alias_name}")

        # If the key alias does not exist, create a new key
        try:
            response = kms_client.create_key(
                Description=f"KMS key for user {self.username}",
                KeyUsage='ENCRYPT_DECRYPT',
                Origin='AWS_KMS'
            )
            key_id = response['KeyMetadata']['KeyId']
            logger.info(f"Created KMS key with ID: {key_id} for user {self.username}")

            # Create an alias for the new key
            kms_client.create_alias(
                AliasName=alias_name,
                TargetKeyId=key_id
            )
            logger.info(f"Created alias {alias_name} for KMS key {key_id}")

            user = User.get(User.username == self.username)
            KMSKeys.create(
                user=user,
                key_alias=alias_name,
                key_id=key_id)

            return key_id
        except ClientError as e:
            logger.error(f"Failed to create KMS key: {e}")
            raise

    def encrypt_file_with_kms(self, kms_client, key_id, plaintext):
        response = kms_client.encrypt(
            KeyId=key_id,
            Plaintext=plaintext
        )
        return response['CiphertextBlob']

    def decrypt_file_with_kms(self, kms_client, ciphertext_blob):
        response = kms_client.decrypt(
            CiphertextBlob=ciphertext_blob
        )
        return response['Plaintext']

    def create_s3_bucket_if_not_exists(self, s3_client, bucket_name):
        try:
            s3_client.head_bucket(Bucket=bucket_name)
            logger.info(f"Bucket '{bucket_name}' already exists.")
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={
                        'LocationConstraint': s3_client.meta.region_name
                    }
                )
                logger.info(f"Bucket '{bucket_name}' created.")
            else:
                raise e

    def create_instance_key(self):
        session = self.setup_boto_session()
        ec2_client = session.client('ec2')
        s3_client = session.client('s3')
        kms_client = session.client('kms')

        username = self.username.replace('_', '-')
        key_name = f"{username}-{self.container_name}"

        # S3 bucket name for storing the keys
        s3_bucket_name = f"{username}-secret-keys"
        
        kms_key_id = self.create_kms_key()

        # Create the S3 bucket if it doesn't exist
        self.create_s3_bucket_if_not_exists(s3_client, s3_bucket_name)

        try:
            ec2_client.describe_key_pairs(KeyNames=[key_name])
            logger.info(f"Can't create as key pair '{key_name}' already exists.")

        except ClientError as e:
            if 'InvalidKeyPair.NotFound' in str(e):
                key_pair_info = ec2_client.create_key_pair(KeyName=key_name)
                private_key = key_pair_info['KeyMaterial']

                # Encrypt the private key using KMS
                encrypted_key = self.encrypt_file_with_kms(kms_client, kms_key_id, private_key.encode('utf-8'))

                # Save encrypted key to S3
                s3_file_path = f"keys/{key_name}.pem.enc"
                s3_client.put_object(Bucket=s3_bucket_name, Key=s3_file_path, Body=encrypted_key)
                logger.info(f"Encrypted key pair saved to s3://{s3_bucket_name}/{s3_file_path}")

                # Save file path to database
                user = User.get(User.username == self.username)
                EC2KeyPair.create(
                    user=user,
                    key_pair=key_name,
                    s3_file_path=f"s3://{s3_bucket_name}/{s3_file_path}"
                )
                logger.info(f"File path saved to database: {s3_file_path}")

            else:
                raise e
        return key_name

    def retrieve_and_decrypt_key(self, s3_file_path, s3_bucket):
        session = self.setup_boto_session()
        s3_client = session.client('s3')
        kms_client = session.client('kms')

        # Retrieve the encrypted key from S3
        response = s3_client.get_object(Bucket=s3_bucket, Key=s3_file_path)
        encrypted_key = response['Body'].read()

        # Decrypt the key using KMS
        decrypted_key = self.decrypt_file_with_kms(kms_client, encrypted_key)
        return decrypted_key.decode('utf-8')

    def find_ami_id(self):
        try:
            session = self.setup_boto_session()
            ec2_client = session.client('ec2')
            filters = [
                {'Name': 'ImageLocation', 'Values': ['amazon/ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*']},
                {'Name': 'State', 'Values': ['available']}
            ]

            response = ec2_client.describe_images(Filters=filters)

            # Sort the AMIs by creation date in descending order
            sorted_amis = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)

            # Return the latest AMI ID if any
            return sorted_amis[0]['ImageId'] if sorted_amis else None
        except ClientError as e:
            # If credentials are invalid, a ClientError will be thrown
            error_code = e.response['Error']['Code']
            if error_code in ('AuthFailure', 'UnauthorizedOperation', 'InvalidClientTokenId', 'AccessDenied'):
                logger.info(f"Authentication to AWS failed: {e.response['Error']['Message']}")
            else:
                logger.info(f"An error occurred: {e.response['Error']['Message']}")
            return None
        except Exception as e:
            # Handle any other exceptions
            logger.info(f"An unexpected error occurred: {e}")
            return None

    def create_security_group(self, http_ports=None, ip_ranges=None):
        session = self.setup_boto_session()
        ec2_client = session.client('ec2')
        username = self.username.replace('_', '-')
        group_name = f"{username}-{self.container_name}-sg"
        description = f"Security group for {self.container_name} host"

        # Check if the security group already exists
        try:
            groups = ec2_client.describe_security_groups(GroupNames=[group_name])
            logger.info(f"Security group '{group_name}' already exists.")
            return groups['SecurityGroups'][0]['GroupId']
        except ec2_client.exceptions.ClientError as e:
            # If a security group with the given name does not exist, create it
            if 'InvalidGroup.NotFound' in str(e):
                security_group = ec2_client.create_security_group(GroupName=group_name,
                                                                  Description=description)
                security_group_id = security_group['GroupId']
                logger.info(f"Security group '{group_name}' created with ID '{security_group_id}'.")
            else:
                raise e

        # Default to allowing all IPs if none are provided
        if ip_ranges is None:
            ip_ranges = [{'CidrIp': '0.0.0.0/0'}]

        # Prepare the list of permission rules
        ip_permissions = [
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': ip_ranges
            }
        ]

        # Add HTTP port(s) if provided
        if http_ports:
            if not isinstance(http_ports, list):
                http_ports = [http_ports]
            for port in http_ports:
                ip_permissions.append({
                    'IpProtocol': 'tcp',
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': ip_ranges
                })

        # # Authorize the ingress rules in one call
        # ec2_client.authorize_security_group_ingress(GroupId=security_group_id,
        #                                                 IpPermissions=ip_permissions)

        #     # Retrieve the existing rules for the security group
        # existing_rules = ec2_client.describe_security_group_rules(
        #     Filters=[
        #         {'Name': 'group-id', 'Values': [security_group_id]}
        #     ]
        # )

        # # Extract existing rules' ports and IP ranges for comparison
        # existing_ports_ip_ranges = [
        #     (rule['FromPort'], rule['ToPort'], tuple(ip_range['CidrIp'] for ip_range in rule['IpRanges']))
        #     for rule in existing_rules['SecurityGroupRules']
        #     if rule['IpProtocol'] == 'tcp'
        # ]

        # # Filter out rules that already exist in the security group
        # ip_permissions = [
        #     rule for rule in ip_permissions
        #     if (rule['FromPort'], rule['ToPort'], tuple(ip_range['CidrIp'] for ip_range in rule['IpRanges'])) not in existing_ports_ip_ranges
        # ]

        # Authorize the ingress rules in one call if there are new rules to add
        if ip_permissions:
            ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=ip_permissions
            )
            logger.info(f"New ingress rules added to the security group '{group_name}'.")
        else:
            logger.info(f"No new ingress rules needed for the security group '{group_name}'.")

        user = User.get(User.username == self.username)
        SecurityGroups.create(
            user=user,
            security_group_name=group_name,
            security_group_id=security_group_id
        )

        user = User.get(User.username == self.username)
        SecurityGroups.create(
            user=user,
            security_group_name=group_name,
            security_group_id=security_group_id
        )

        return security_group_id

    def create_ec2_instance(self):
        session = self.setup_boto_session()
        ec2_client = session.client('ec2')
        username = self.username.replace('_', '-')
        instance_name = f"{username}-{self.container_name}"

        logger.info(f"Creating EC2 instance with name: {instance_name}")

        # !!!!! Should fix
        # Find the AMI ID
        # ami_id = self.find_ami_id()
        # if not ami_id:
        #     raise ValueError(f"Unable to find a suitable AMI ID. The output: {ami_id}")

        ami_id = "ami-026c3177c9bd54288"

        key_name = self.create_instance_key()
        if not key_name:
            raise ValueError("Unable to create a key pair.")

        security_group_id = self.create_security_group()
        if not security_group_id:
            raise ValueError("Unable to create a security group.")

        instance_type = self.find_best_instance_type()
        if not instance_type:
            raise ValueError("Unable to find a suitable instance type.")

        ebs_volume_size_gb = self.calculate_ebs_volume_size(self.requested_storage)

        with open('api/services/user_data.sh', 'r') as file:
            user_data_script = file.read()

        block_device_mappings = [
            {
                'DeviceName': '/dev/sdh',
                'Ebs': {
                    'VolumeSize': ebs_volume_size_gb,
                    'DeleteOnTermination': True,
                    'VolumeType': 'gp2',
                },
            },
        ]

        try:
            instances = ec2_client.run_instances(
                ImageId=ami_id,
                MinCount=1,
                MaxCount=1,
                InstanceType=instance_type,
                KeyName=key_name,
                SecurityGroupIds=[security_group_id],
                UserData=user_data_script,
                BlockDeviceMappings=block_device_mappings,
                TagSpecifications=[
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': instance_name
                            }
                        ]
                    }
                ]
            )
            instance_id = instances['Instances'][0]['InstanceId']
            logger.info(f"EC2 instance '{instance_id}' has been created successfully.")

            # Log the full response to debug the missing PublicIpAddress
            logger.info(f"Full instance creation response: {instances}")

            # Retry mechanism to fetch public IP address
            public_ip = None
            retry_count = 5
            while retry_count > 0 and public_ip is None:
                instance_description = ec2_client.describe_instances(InstanceIds=[instance_id])
                public_ip = instance_description['Reservations'][0]['Instances'][0].get('PublicIpAddress')
                if public_ip is None:
                    time.sleep(5)  # Wait for 5 seconds before retrying
                    retry_count -= 1

            if public_ip is None:
                raise ValueError(f"Failed to fetch public IP address for instance '{instance_id}'.")

            logger.info(f"EC2 instance '{instance_id}' has been created successfully with public IP '{public_ip}'.")

            user = User.get(User.username == self.username)
            key_pair = EC2KeyPair.get(EC2KeyPair.key_pair == key_name)
            security_group = SecurityGroups.get(SecurityGroups.security_group_id == security_group_id)

            EC2Instances.create(
                user=user,
                ec2_instance_id=instance_id,
                security_group=security_group,  # Use the foreign key field here
                key_file=key_pair
            )
            logger.info(f"EC2 instance record created successfully in the database.")

            return instance_id, public_ip

        except Exception as e:
            logger.error(f"Failed to create EC2 instance: {e}")
            raise


class InstanceCleanUp():
    def __init__(self, aws_access_key, aws_secret_key, aws_region=None):
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.aws_region = aws_region

    def setup_boto_session(self):
        session = boto3.Session(
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key,
            region_name=self.aws_region
        )
        return session

    def delete_key_pair(self, key_name):
        session = self.setup_boto_session()
        ec2_client = session.client('ec2')
        try:
            ec2_client.delete_key_pair(KeyName=key_name)
            logger.info(f"Key pair '{key_name}' has been deleted.")
        except Exception as e:
            logger.info(f"Failed to delete key pair '{key_name}': {e}")

    def delete_security_group(self, security_group_id):
        session = self.setup_boto_session()
        ec2_client = session.client('ec2')
        try:
            ec2_client.delete_security_group(GroupId=security_group_id)
            logger.info(f"Security group '{security_group_id}' has been deleted.")
        except Exception as e:
            logger.info(f"Failed to delete security group '{security_group_id}': {e}")

    def terminate_ec2_instance(self, instance_id):
        session = self.setup_boto_session()
        ec2_client = session.client('ec2')
        try:
            ec2_client.terminate_instances(InstanceIds=[instance_id])
            logger.info(f"EC2 instance '{instance_id}' has been terminated.")
        except Exception as e:
            logger.info(f"Failed to terminate EC2 instance '{instance_id}': {e}")
