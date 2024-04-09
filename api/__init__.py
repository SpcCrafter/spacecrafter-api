import os
import logging
from flask import Flask
from flask_jwt_extended import JWTManager
from api.database import database_details, database
from api.aws import get_ssm_parameter
from api.controllers import user_controller, aws_credentials_controller

app = Flask(__name__)

env = os.environ.get('FLASK_ENV')
if env == 'prod':
    app.config['JWT_SECRET_KEY'] = get_ssm_parameter('/api/jwt_secret_key')
elif env == 'dev':
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

jwt = JWTManager(app)
jwt.init_app(app)

app.config.update(database_details)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

@app.before_request
def before_request():
    database.connect(reuse_if_open=True)

@app.teardown_request
def after_request(_exception=None):
    if not database.is_closed():
        database.close()

app.register_blueprint(user_controller.user_bp, url_prefix='/api')
app.register_blueprint(aws_credentials_controller.aws_credentials_bp, url_prefix='/api')


if __name__ == "__main__":
    app.run()
