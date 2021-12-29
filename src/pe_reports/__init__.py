"""The pe_reports library."""
# We disable a Flake8 check for "Module imported but unused (F401)" here because
# although this import is not directly used, it populates the value
# package_name.__version__, which is used to get version information about this
# Python package.

# Third-Party Libraries
# Third party packages
from flask import Flask

# cisagov Libraries
from pe_reports.stakeholder.views import stakeholder_blueprint

from ._version import __version__  # noqa: F401

__all__ = ["pages", "report_generator", "stylesheet"]

# Flask implementation
app = Flask(__name__)
app.config["SECRET_KEY"] = "bozotheclown"
app.config["SWLALCHEMY_DATABASE_URI"] = "postgresql://postgres:"


# Register the flask apps
app.register_blueprint(stakeholder_blueprint)
