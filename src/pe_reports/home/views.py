"""Flask application will add new stakeholder information to the PE Database.

Automate the process to add stakeholder information to Cyber Sixgill portal.
"""

# Third-Party Libraries
from flask import Blueprint, render_template

home_blueprint = Blueprint("home", __name__, template_folder="templates/home")


@home_blueprint.route("/")
def index():
    """Create "add customer" HTML form.

    Gather data from form and insert into database.
    """
    return render_template("home.html")
