"""Create the page forms."""

# Third-Party Libraries
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired


class InfoFormExternal(FlaskForm):
    """Create web form to take user input on organization information/details."""

    cust = StringField("What is the stakeholder name?", validators=[DataRequired()])
    # custIP = StringField(
    #     "What is the stakeholder ip/cidr? *comma separate entries",
    #     validators=[DataRequired()],
    # )
    custRootDomain = StringField(
        "What is the root domain for this stakeholder? " "*comma separate entries"
    )
    custDomainAliases = StringField(
        "What are the organization aliases? " "*comma separate entries"
    )
    # custSubDomain = StringField(
    #     "What is the sub-domain for this stakeholder?" " *comma separate entries"
    # )
    custExecutives = StringField(
        "Who are the Excutive for this stakeholder? " "*comma separate entries"
    )
    submit = SubmitField("Submit", render_kw={"onclick": "loading()"})
