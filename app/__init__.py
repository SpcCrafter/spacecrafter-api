from flask import Flask
import boto3
import os
from peewee import MySQLDatabase
from app.models.user import User
from app.controllers.user_controller import user_bp

app = Flask(__name__)

ssm_client = boto3.client('ssm', region_name=os.environ.get('AWS_REGION'))

def get_parameter(name, with_decryption=True):
    try:
        response = ssm_client.get_parameter(Name=name, WithDecryption=with_decryption)
        return response['Parameter']['Value']
    except Exception as e:
        print(f"Error fetching parameter {name}: {e}")


app.config['DB_NAME'] = get_parameter('/db/name')
app.config['DB_USER'] = get_parameter('/db/user')
app.config['DB_PASSWORD'] = get_parameter('/db/password')
app.config['DB_HOST'] = get_parameter('/db/host')  # Should resolve via Route 53
app.config['DB_PORT'] = 3306


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