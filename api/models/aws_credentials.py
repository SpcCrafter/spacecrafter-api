from peewee import Model, ForeignKeyField, CharField
from api.database import database
from .user import User

class AwsCredentials(Model):
    user = ForeignKeyField(User, backref='aws_credentials')
    aws_access_key_id = CharField()
    aws_secret_access_key = CharField()
    preferred_aws_region = CharField(null=True)

    class Meta:
        database = database
        table_name = 'aws_credentials'
