"""The pe_reports library."""
# We disable a Flake8 check for "Module imported but unused (F401)" here because
# although this import is not directly used, it populates the value
# package_name.__version__, which is used to get version information about this
# Python package.

# Standard Python Libraries
# Local packages
# from pe_reports.home.views import home_blueprint
# from pe_reports.manage_login.views import manage_login_blueprint

# Standard Python Libraries
import logging
import os

# Third-Party Libraries
# Third party packages
from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

# cisagov Libraries
from pe_reports.data.config import config
from pe_reports.home.views import home_blueprint

# Stakeholder views
from pe_reports.stakeholder.views import stakeholder_blueprint

from ._version import __version__  # noqa: F401

params = config()
login_manager = LoginManager()
# Flask implementation
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = f'postgresql+psycopg2://{params["user"]}:{params["password"]}@{params["host"]}:{params["port"]}/{params["database"]}'


# Config DB
db = SQLAlchemy(app)
Migrate(app, db)


# login_manager.init_app(app)
# login_manager.login_view = "login"

__all__ = ["pages", "report_generator", "stylesheet", "app"]

# cisagov Libraries


# Register the flask apps
app.register_blueprint(stakeholder_blueprint)
# app.register_blueprint(manage_login_blueprint)
app.register_blueprint(home_blueprint)


if __name__ == "__main__":
    logging.info("The program has started...")
    app.run(host="127.0.0.1", debug=False, port=8000)
