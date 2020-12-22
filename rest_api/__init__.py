from flask import Flask
from rest_api.config import Config
from rest_api.models import db


def create_app(config_class=Config):

    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    # with app.app_context():
    #     db.create_all()

    from rest_api.users.routes import users
    app.register_blueprint(users)

    return app
