from api.models.user import User

def create_user(username, email, password):
    user = User.create(username=username, email=email, password=password)
    return user

def find_user_by_username(username):
    try:
        return User.get(User.username == username)
    except User.DoesNotExist:
        return None

# These functions check for the existence of a username or email in the database
def user_exists(username):
    return User.select().where(User.username == username).exists()

def email_exists(email):
    return User.select().where(User.email == email).exists()