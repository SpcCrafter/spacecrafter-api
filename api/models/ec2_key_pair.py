from peewee import Model, ForeignKeyField, CharField
from api.database import database
from .user import User

class EC2KeyPair(Model):
    user = ForeignKeyField(User, backref='ec2_key_pair')
    key_pair = CharField()
    s3_file_path = CharField()

    class Meta:
        database = database
        table_name = 'ec2_key_pair'
