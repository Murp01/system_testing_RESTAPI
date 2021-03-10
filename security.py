from werkzeug.security import safe_str_cmp
from models.user import UserModel
from flask_jwt import JWT, JWTError

def authenticate(username, password):
    """
    Function that gets called when a user calls the /auth endpoint with their username and password.
    :param username: user's username in string format
    :param password: User's unencrypted password in string formate
    :return: A usermodel object if authentication was successful, none otherwise.
    """
    user = UserModel.find_by_username(username)
    if user and safe_str_cmp(user.password, password):
        return user

def identity(payload):
    """
    Function that gets called when a user has already authenticated, and Flask-JWT verified their authorization header
    is correct
    :param payload:  a dictionary with 'identity key, which is the user id
    :return: A user model object
    """

    user_id = payload['identity']
    return UserModel.find_by_id(user_id)