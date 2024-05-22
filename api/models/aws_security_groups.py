from peewee import Model, ForeignKeyField, CharField
from api.database import database
from .user import User

class SecurityGroups(Model):
    user = ForeignKeyField(User, backref='security_groups')
    security_group_name = CharField()
    security_group_id = CharField()

    class Meta:
        database = database
        table_name = 'security_groups'
