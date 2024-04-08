import os
import logging
from flask import Flask
from peewee import MySQLDatabase
import boto3
from botocore.exceptions import ClientError
from models.user import User
from controllers.user_controller import user_bp

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

ssm_client = boto3.client('ssm', region_name=os.environ.get('AWS_REGION'))

def get_parameter(name, with_decryption=True):
    try:
        response = ssm_client.get_parameter(Name=name, WithDecryption=with_decryption)
        return response['Parameter']['Value']
    except ClientError as e:
        logger.error(f"Error fetching parameter {name}: {e}")
        raise  # Rethrow the exception if you want to handle it further up the call stack
    except Exception as e:
        logger.error(f"Unexpected error fetching parameter {name}: {e}")
        raise  # Rethrow the exception to ensure the application does not run with invalid config

class Config:
    DB_PORT = 3306
    # Add other common config settings here

class DevelopmentConfig(Config):
    DB_NAME = os.environ.get('DEV_DB_NAME')
    DB_USER = os.environ.get('DEV_DB_USER')
    DB_PASSWORD = os.environ.get('DEV_DB_PASSWORD')
    DB_HOST = os.environ.get('DEV_DB_HOST')

class ProductionConfig(Config):
    DB_NAME = get_parameter('/db/name')
    DB_USER = get_parameter('/db/user')
    DB_PASSWORD = get_parameter('/db/password')
    DB_HOST = get_parameter('/db/host') # Should resolve via Route 53

env = os.environ.get('FLASK_ENV')
if env == 'dev':
    app.config.from_object(DevelopmentConfig)
elif env == 'prod':
    ssm_client = boto3.client('ssm', region_name=os.environ.get('AWS_REGION'))
    app.config.from_object(ProductionConfig())
else:
    raise EnvironmentError("The FLASK_ENV environment variable is not set correctly. "
                            "Please set it to 'dev' or 'prod'.")

database = MySQLDatabase(
    app.config['DB_NAME'],
    user=app.config['DB_USER'],
    password=app.config['DB_PASSWORD'],
    host=app.config['DB_HOST'],
    port=app.config['DB_PORT']
)


@app.before_first_request
def initialize_database():
    # Connect to the database and create tables if they don't exist
    with database:
        database.create_tables([User], safe=True)

app.register_blueprint(user_bp, url_prefix='/api')
