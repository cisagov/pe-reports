"""Create the stakeholder data input form."""

# Third-Party Libraries
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField


class InfoFormExternal(FlaskForm):
    """Create web form to take user input on report to be generated."""

    report_date = StringField(
        "What is the report date? (Final day of the report period, either the 15th or last day of the month)"
        "*format YYYY-MM-DD"
    )
    output_directory = StringField(
        "The directory where the final PDF reports should be saved. "
    )

    submit = SubmitField("Submit", render_kw={"onclick": "loading()"})


class BulletinFormExternal(FlaskForm):
    """Create web form to take user input on bulletin to be generated."""

    cybersix_id = StringField("Cybersix Intel Item ID:")
    user_input = TextAreaField(
        "Please provide an explanation of what was found in the post/intel_item."
    )
    output_directory1 = StringField("Output Directory:")
    file_name = StringField("File Name?")

    submit1 = SubmitField("Submit", render_kw={"onclick": "loading()"})


class CredsFormExternal(FlaskForm):
    """Create web form to take user input on bulletin to be generated."""

    org_id = StringField("Organization Cyhy ID:")
    breach_name = StringField("Breach Name:")

    submit2 = SubmitField("Submit", render_kw={"onclick": "loading()"})
