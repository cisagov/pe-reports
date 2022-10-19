"""The pe_reports library."""
# We disable a Flake8 check for "Module imported but unused (F401)" here because
# although this import is not directly used, it populates the value
# package_name.__version__, which is used to get version information about this
# Python package.

# Standard Python Libraries
import logging
import os

# Third-Party Libraries
import celery
from flask import Flask, render_template
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

# cisagov Libraries
from pe_reports.data.config import config

# Stakeholder views
from pe_reports.home.views import home_blueprint
from pe_reports.stakeholder.views import stakeholder_blueprint
from pe_reports.stakeholder_full.views import stakeholder_full_blueprint
from pe_reports.stakeholder_lite.views import stakeholder_lite_blueprint

from ._version import __version__  # noqa: F401

# from werkzeug.utils import secure_filename

params = config()
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
app.config["UPLOAD_FOLDER"] = "src/pe_reports/uploads/"
app.config["ALLOWED_EXTENSIONS"] = {"txt", "csv"}


# Create central logging
logging.basicConfig(
    filename="flaskLog.log",
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level=logging.INFO,
)


# Creates a Celery object
celery_obj = celery.Celery(app.name, broker=app.config["CELERY_BROKER_URL"])
celery_obj.conf.update(app.config)

# Config DB
db = SQLAlchemy(app)
Migrate(app, db)

# TODO: Add a login page in the future. Issue #207 contains details
# login_manager.init_app(app)
# login_manager.login_view = "login"

__all__ = ["app", "pages", "report_generator", "stylesheet"]


# Register the flask apps
app.register_blueprint(stakeholder_blueprint)
app.register_blueprint(stakeholder_lite_blueprint)
app.register_blueprint(stakeholder_full_blueprint)
# TODO: Add login blueprint. Issue #207 contains details
# app.register_blueprint(manage_login_blueprint)
app.register_blueprint(home_blueprint)


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")


if __name__ == "__main__":
    logging.info("The program has started...")
    app.run(host="127.0.0.1", debug=False, port=8000)
