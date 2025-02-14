from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from config import Config

# Initialize Flask extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message_category = "info"

# Create Flask App Factory
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions with app
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    # Import and register blueprints (routes)
    from app.routes import main
    app.register_blueprint(main)

    return app
