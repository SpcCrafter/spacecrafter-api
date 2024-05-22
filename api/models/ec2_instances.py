from peewee import Model, ForeignKeyField, CharField
from api.database import database
from .ec2_key_pair import EC2KeyPair
from .aws_security_groups import SecurityGroups
from .user import User

class EC2Instances(Model):
    user = ForeignKeyField(User, backref='ec2_instances')
    ec2_instance_id = CharField()
    security_group = ForeignKeyField(SecurityGroups, backref='ec2_instances')
    key_file = ForeignKeyField(EC2KeyPair, backref='ec2_instances')

    class Meta:
        database = database
        table_name = 'ec2_instances'
