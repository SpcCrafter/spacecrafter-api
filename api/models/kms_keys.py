from peewee import Model, ForeignKeyField, CharField
from api.database import database
from .user import User

class KMSKeys(Model):
    user = ForeignKeyField(User, backref='kms_keys')
    key_alias = CharField()
    key_id = CharField()

    class Meta:
        database = database
        table_name = 'kms_keys'
