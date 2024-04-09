from flask_bcrypt import generate_password_hash, check_password_hash
from peewee import IntegrityError
from api.models.user import User
from api.repositories import user_repository

def create_user(username, email, raw_password):
    hashed_password = generate_password_hash(raw_password)
    try:
        user = user_repository.create_user(username, email, hashed_password)
        return user
    except IntegrityError:
        return None

def verify_user(username, password):
    user = user_repository.find_user_by_username(username)
    if user and check_password_hash(user.password, password):
        return user
    return None

# These functions call the respective functions in the repository
def user_exists(username):
    return user_repository.user_exists(username)

def email_exists(email):
    return user_repository.email_exists(email)
