import os
from peewee import MySQLDatabase
from api.aws import get_ssm_parameter

env = os.environ.get('FLASK_ENV')
if env == 'prod':
    db_name = get_ssm_parameter('/db/name')
    db_user = get_ssm_parameter('/db/user')
    db_password = get_ssm_parameter('/db/password')
    db_host = get_ssm_parameter('/db/host') # Should resolve via Route 53
    db_port = get_ssm_parameter('/db/port')
elif env == 'dev':
    db_name = os.getenv('DEV_DB_NAME')
    db_user = os.getenv('DEV_DB_USER')
    db_password = os.getenv('DEV_DB_PASSWORD')
    db_host = os.getenv('DEV_DB_HOST')
    db_port = int(os.getenv('DEV_DB_PORT'))
else:
    raise EnvironmentError("The FLASK_ENV environment variable is not set correctly. "
                        "Please set it to 'dev' or 'prod'.")

database_details = {
    'db_name': db_name,
    'db_user': db_user,
    'db_password': db_password,
    'db_host': db_host,
    'db_port': db_port
}

database = MySQLDatabase(
    database_details['db_name'],
    user=database_details['db_user'],
    password=database_details['db_password'],
    host=database_details['db_host'],
    port=database_details['db_port']
)
