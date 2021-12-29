"""Flask application will add new stakeholder information to the PE Database.

Automate the process to add stakeholder information to Cyber Sixgill portal.
"""
# Standard Python Libraries

# Standard Python Libraries
import logging

# Third-Party Libraries
# Local file import
# from data.config import config1, config2
from flask import render_template

# cisagov Libraries
from pe_reports import app


@app.route("/", methods=["GET", "POST"])
def index():
    """Create add customer html form.

    Gather data from form and insert into database.
    """
    return render_template("home.html")


if __name__ == "__main__":
    logging.info("The program has started...")
    app.run(debug=False, ***REMOVED***8000)
