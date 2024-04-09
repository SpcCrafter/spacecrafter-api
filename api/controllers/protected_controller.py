from flask_jwt_extended import jwt_required
from flask import Blueprint, jsonify

protected_bp = Blueprint('protected_bp', __name__)

@protected_bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify(msg="This is a protected endpoint")
