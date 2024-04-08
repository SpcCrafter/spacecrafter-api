from peewee import Model, CharField, BooleanField, PrimaryKeyField
from api import database

class User(Model):
    id = PrimaryKeyField()
    username = CharField(unique=True)
    password = CharField()
    email = CharField()
    is_active = BooleanField(default=True)

    class Meta:
        database = database
        table_name = 'users'
