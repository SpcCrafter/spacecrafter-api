from flask import Blueprint
from flask_jwt_extended import jwt_required
from api.controllers.aws_credentials_controller import aws_credentials_bp

v1_bp = Blueprint('v1_bp', __name__, url_prefix='/api/v1')

v1_bp.register_blueprint(aws_credentials_bp)

@v1_bp.before_request
@jwt_required()
def jwt_protected():
    pass  # No need to do anything here, the presence of a valid JWT token will be verified
