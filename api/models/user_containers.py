from peewee import Model, ForeignKeyField, CharField
from api.database import database
from .ec2_instances import EC2Instances
from .user import User

class UserContainers(Model):
    user = ForeignKeyField(User, backref='user_containers')
    container_name = CharField()
    ec2_instance = ForeignKeyField(EC2Instances, backref='user_containers')

    class Meta:
        database = database
        table_name = 'user_containers'
