"""The pe_reports library."""
# We disable a Flake8 check for "Module imported but unused (F401)" here because
# although this import is not directly used, it populates the value
# package_name.__version__, which is used to get version information about this
# Python package.

# Third-Party Libraries
# Third party packages
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from pe_reports.data.config import config
from flask_mail import Mail



from ._version import __version__  # noqa: F401


params = config()
login_manager = LoginManager()
# Flask implementation
app = Flask(__name__)
app.config["SECRET_KEY"] = "bozotheclown"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SQLALCHEMY_DATABASE_URI"] = f'postgresql+psycopg2://{params["user"]}:{params["password"]}@{params["host"]}:{params["port"]}/{params["database"]}'

# Config DB
db = SQLAlchemy(app)
Migrate(app, db)

# Stakeholder views
from pe_reports.stakeholder.views import stakeholder_blueprint
from pe_reports.manage_login.views import manage_login_blueprint


login_manager.init_app(app)
login_manager.login_view = 'login'

__all__ = ["pages", "report_generator", "stylesheet"]

# Register the flask apps
app.register_blueprint(stakeholder_blueprint)
app.register_blueprint(manage_login_blueprint)
