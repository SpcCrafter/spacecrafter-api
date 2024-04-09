import os
import boto3
from botocore.exceptions import ClientError

def get_ssm_parameter(name):
    ssm_client = boto3.client('ssm', region_name=os.getenv('AWS_REGION'))
    try:
        response = ssm_client.get_parameter(Name=name, WithDecryption=True)
        return response['Parameter']['Value']
    except ClientError as e:
        print(f"Error fetching parameter {name}: {e}")
        return None
