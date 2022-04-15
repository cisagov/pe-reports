"""Flask application will add new stakeholder information to the PE Database.

Automate the process to add stakeholder information to Cyber Sixgill portal.
"""
# Standard Python Libraries

# Standard Python Libraries


# Third-Party Libraries
# Local file import
# from data.config import config1, config2

# Third-Party Libraries
from flask import Blueprint, render_template

home_blueprint = Blueprint("home", __name__, template_folder="templates/home")


@home_blueprint.route("/")
# @app.route("/", methods=["GET", "POST"])
def index():
    """Create add customer html form.

    Gather data from form and insert into database.
    """
    return render_template("home.html")
