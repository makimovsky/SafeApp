from flask import Flask
from flask_login import LoginManager
from .routes.auth import auth_bp
from .routes.main import main_bp
from .routes.user_page import user_bp

login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

    login_manager.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(user_bp)

    return app
