from flask_jwt_extended import create_access_token
from flask import Blueprint, request, jsonify
from api.services.user_services import create_user, verify_user, user_exists, email_exists

user_bp = Blueprint('user_bp', __name__)

@user_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'error': 'Username, email, and password are required'}), 400

    if user_exists(username):
        return jsonify({'error': 'Username is already taken'}), 409

    if email_exists(email):
        return jsonify({'error': 'Email is already registered'}), 409

    user = create_user(username, email, password)
    if user:
        return jsonify({'username': user.username, 'email': user.email}), 201
    else:
        return jsonify({'error': 'User could not be created'}), 500


@user_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = verify_user(username, password)
    if user:
        # Create JWT token
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401
