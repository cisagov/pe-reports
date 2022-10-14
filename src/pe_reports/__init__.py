"""The pe_reports library."""
# We disable a Flake8 check for "Module imported but unused (F401)" here because
# although this import is not directly used, it populates the value
# package_name.__version__, which is used to get version information about this
# Python package.

# Standard Python Libraries
import logging
import os
# from typing import Union, Any
# from datetime import timedelta, datetime

# Third-Party Libraries
from celery import Celery
from fastapi import FastAPI
from fastapi.middleware.wsgi import WSGIMiddleware
from fastapi.security import OAuth2PasswordBearer
from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import uvicorn
# from jose import jwt


# cisagov Libraries
from pe_reports.data.config import config

# API Endpoints
from pe_reports.data_API import itemEndpoints

# from pe_reports.data_API import models
# from pe_reports.manage_login import models

from ._version import __version__  # noqa: F401

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

CENTRAL_LOGGING_FILE = "pe_reports_logging.log"
DEBUG = True
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

# FASTAPI section
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
ALGORITHM = "HS256"
JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]
JWT_REFRESH_SECRET_KEY = os.environ["JWT_REFRESH_SECRET_KEY"]
fastapp = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# All api routes to be shared here
fastapp.include_router(itemEndpoints.router)

# Creates a Celery object
celery = Celery(app.name, broker=app.config["CELERY_BROKER_URL"])
celery.conf.update(app.config)

# Config DB
db = SQLAlchemy(app)
Migrate(app, db)

# TODO: Add a login page in the future. Issue #207 contains details
login_manager.init_app(app)
login_manager.login_view = "login"

__all__ = ["app", "pages", "report_generator", "stylesheet", "fastapp", 'db']

# cisagov Libraries
from pe_reports.home.views import home_blueprint
from pe_reports.manage_login.views import manage_login_blueprint
from pe_reports.stakeholder.views import stakeholder_blueprint

# Register the flask apps
app.register_blueprint(stakeholder_blueprint)
app.register_blueprint(manage_login_blueprint)
app.register_blueprint(home_blueprint)

# FastAPI endpoint. The following line is what enables fastAPI to work along flask.
fastapp.mount("/", WSGIMiddleware(app))

# from pe_reports.data_API import models
from pe_reports.manage_login import models

if __name__ == "__main__":
    logging.info("The program has started...")
    uvicorn.run(fastapp, host="127.0.0.1", debug=DEBUG, port=8000)
    # app.run(host="127.0.0.1", debug=DEBUG, port=8000)
