"""The pe_reports library."""
# We disable a Flake8 check for "Module imported but unused (F401)" here because
# although this import is not directly used, it populates the value
# package_name.__version__, which is used to get version information about this
# Python package.

# Standard Python Libraries
import logging
import os

# Third-Party Libraries
from celery import Celery
from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

# cisagov Libraries
from pe_reports.data.config import config

# Stakeholder views
from pe_reports.home.views import home_blueprint
from pe_reports.stakeholder.views import stakeholder_blueprint

from ._version import __version__  # noqa: F401

params = config()
if params["port"] == "":
    logging.info("Empty port. Setting to 5000.")
    params["port"] = 5000
login_manager = LoginManager()
# Flask implementation
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = f'postgresql+psycopg2://{params["user"]}:{params["password"]}@{params["host"]}:{params["port"]}/{params["database"]}'


# Configure the redis server
app.config["CELERY_BROKER_URL"] = "redis://localhost:6379/0"
app.config["CELERY_RESULT_BACKEND"] = "redis://localhost:6379/0"

CENTRAL_LOGGING_FILE = "pe_reports_logging.log"
DEBUG = False
# Setup Logging
"""Set up logging and call the run_pe_script function."""
if DEBUG is True:
    level = "DEBUG"
else:
    level = "INFO"

logging.basicConfig(
    filename=CENTRAL_LOGGING_FILE,
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level=level,
)

app.config["LOGGER"] = logging.getLogger(__name__)

# Creates a Celery object
celery = Celery(app.name, broker=app.config["CELERY_BROKER_URL"])
celery.conf.update(app.config)

# Config DB
db = SQLAlchemy(app)
Migrate(app, db)

# TODO: Add a login page in the future. Issue #207 contains details
# login_manager.init_app(app)
# login_manager.login_view = "login"

__all__ = ["app", "pages", "report_generator", "stylesheet"]


# Register the flask apps
app.register_blueprint(stakeholder_blueprint)
# TODO: Add login blueprint. Issue #207 contains details
# app.register_blueprint(manage_login_blueprint)
app.register_blueprint(home_blueprint)


if __name__ == "__main__":
    logging.info("The program has started...")
    app.run(host="127.0.0.1", debug=DEBUG, port=8000)
