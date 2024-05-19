import math
import boto3
from botocore.exceptions import ClientError

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
    def __init__(self, user_id, container_name,
                 requested_cpu, requested_storage,
                 aws_secret_key, aws_access_key, aws_region=None):
        self.user_id = user_id
        self.container_name = container_name
        self.requested_storage = requested_storage
        self.requested_cpu = requested_cpu
        self.aws_secret_key = aws_secret_key
        self.aws_access_key = aws_access_key
        self.aws_region = aws_region

    def setup_ec2_session(self):
        session = boto3.Session(
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key,
            region_name=self.aws_region
        )
        ec2_client = session.client('ec2')

        return ec2_client

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

    def create_instance_key(self):
        ec2_client = self.setup_ec2_session()

        key_name = f"{self.user_id}_{self.container_name}"
        # Check if the key pair already exists
        try:
            ec2_client.describe_key_pairs(KeyNames=[key_name])
            print(f"Can't create as key pair '{key_name}' already exists.")
        except ec2_client.exceptions.ClientError as e:
            if 'InvalidKeyPair.NotFound' in str(e):
                key_pair_info = ec2_client.create_key_pair(KeyName=key_name)
                # Save the private key to a file
                with open(f'{key_name}.pem', 'w') as key_file:
                    key_file.write(key_pair_info['KeyMaterial'])
                    print(f"Key pair '{key_name}' created and saved to {key_name}.pem")
            else:
                # Some other error occurred
                raise e
        return key_name

    def find_ami_id(self):
        try:
            ec2_client = self.setup_ec2_session()

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
                print(f"Authentication to AWS failed: {e.response['Error']['Message']}")
            else:
                print(f"An error occurred: {e.response['Error']['Message']}")
            return None
        except Exception as e:
            # Handle any other exceptions
            print(f"An unexpected error occurred: {e}")
            return None

    def create_security_group(self, http_ports=None, ip_ranges=None):
        ec2_client = self.setup_ec2_session()
        group_name = f"{self.user_id}_{self.container_name}_sg"
        description = f"Security group for {self.container_name} host"

        # Check if the security group already exists
        try:
            groups = ec2_client.describe_security_groups(GroupNames=[group_name])
            print(f"Security group '{group_name}' already exists.")
            return groups['SecurityGroups'][0]['GroupId']
        except ec2_client.exceptions.ClientError as e:
            # If a security group with the given name does not exist, create it
            if 'InvalidGroup.NotFound' in str(e):
                security_group = ec2_client.create_security_group(GroupName=group_name,
                                                                  Description=description)
                security_group_id = security_group['GroupId']
                print(f"Security group '{group_name}' created with ID '{security_group_id}'.")
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
            print(f"New ingress rules added to the security group '{group_name}'.")
        else:
            print(f"No new ingress rules needed for the security group '{group_name}'.")

        return security_group_id

    def create_ec2_instance(self):
        ec2_client = self.setup_ec2_session()
        instance_name = f"{self.user_id}_{self.container_name}"
        # !!!!! Should fix
        # Find the AMI ID
        # ami_id = self.find_ami_id()
        # if not ami_id:
        #     raise ValueError(f"Unable to find a suitable AMI ID. The output: {ami_id}")
        ami_id = "ami-026c3177c9bd54288"

        # Create the key pair
        key_name = self.create_instance_key()
        if not key_name:
            raise ValueError("Unable to create a key pair.")

        # Create the security group
        security_group_id = self.create_security_group()
        if not security_group_id:
            raise ValueError("Unable to create a security group.")

        # Find the best instance type based on requested resources
        instance_type = self.find_best_instance_type()
        if not instance_type:
            raise ValueError("Unable to find a suitable instance type.")

        # Calculate the EBS volume size
        ebs_volume_size_gb = self.calculate_ebs_volume_size(self.requested_storage)

        with open('api/services/user_data.sh', 'r') as file:
            user_data_script = file.read()

        # Prepare block device mappings
        block_device_mappings = [
            {
                'DeviceName': '/dev/sdh',
                'Ebs': {
                    'VolumeSize': ebs_volume_size_gb,
                    'DeleteOnTermination': True,
                    'VolumeType': 'gp2',  # General Purpose SSD
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
            print(f"EC2 instance '{instance_id}' has been created successfully.")
            return instance_id
        except Exception as e:
            # Handle the exception in a way that's appropriate for your application
            # For example, you might want to log the error,
            # clean up resources, or retry the operation
            print(f"Failed to create EC2 instance: {e}")
            raise


class InstanceCleanUp():
    def __init__(self, aws_access_key, aws_secret_key, aws_region=None):
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.aws_region = aws_region

    def setup_ec2_session(self):
        session = boto3.Session(
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key,
            region_name=self.aws_region
        )
        ec2_client = session.client('ec2')
        return ec2_client

    def delete_key_pair(self, key_name):
        ec2_client = self.setup_ec2_session()
        try:
            ec2_client.delete_key_pair(KeyName=key_name)
            print(f"Key pair '{key_name}' has been deleted.")
        except Exception as e:
            print(f"Failed to delete key pair '{key_name}': {e}")

    def delete_security_group(self, security_group_id):
        ec2_client = self.setup_ec2_session()
        try:
            ec2_client.delete_security_group(GroupId=security_group_id)
            print(f"Security group '{security_group_id}' has been deleted.")
        except Exception as e:
            print(f"Failed to delete security group '{security_group_id}': {e}")

    def terminate_ec2_instance(self, instance_id):
        ec2_client = self.setup_ec2_session()
        try:
            ec2_client.terminate_instances(InstanceIds=[instance_id])
            print(f"EC2 instance '{instance_id}' has been terminated.")
        except Exception as e:
            print(f"Failed to terminate EC2 instance '{instance_id}': {e}")
