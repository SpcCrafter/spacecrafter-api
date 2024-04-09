import os
import boto3
from botocore.exceptions import ClientError
from flask_jwt_extended import get_jwt_identity
from api.models.user import User
from api.models.aws_credentials import AwsCredentials
from api.utils import decrypt

def get_ssm_parameter(name):
    ssm_client = boto3.client('ssm', region_name=os.getenv('AWS_REGION'))
    try:
        response = ssm_client.get_parameter(Name=name, WithDecryption=True)
        return response['Parameter']['Value']
    except ClientError as e:
        print(f"Error fetching parameter {name}: {e}")
        return None

def get_aws_credentials(current_user_id):
    # current_user_id = get_jwt_identity()

    user = User.get_or_none(username=current_user_id)
    if not user:
        raise Exception(f'User not found')

    aws_credentials = AwsCredentials.get_or_none(user=user)
    if not aws_credentials:
        raise Exception('AWS Credentials not found')

    decrypted_access_key = decrypt(aws_credentials.aws_access_key_id)
    decrypted_secret_key = decrypt(aws_credentials.aws_secret_access_key)

    return decrypted_access_key, decrypted_secret_key
