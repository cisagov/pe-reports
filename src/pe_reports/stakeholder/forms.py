"""Create the page forms."""
# Standard Python Libraries
import logging

# Third-Party Libraries
from flask_wtf import FlaskForm
from pymongo import MongoClient
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired

# cisagov Libraries
from pe_reports.data.config import config2


def cyhyGet():
    """Make connection to cyhyDB and query/return agency information."""
    myinfo = config2()
    host = myinfo["host"]
    user = myinfo["user"]
    password = myinfo["password"]
    port = myinfo["port"]
    dbname = myinfo["database"]
    agencyInfo = {}
    agencyNames = []

    try:

        CONNECTION_STRING = f"mongodb://{user}:{password}@{host}:{port}/{dbname}"

        client = MongoClient(CONNECTION_STRING, serverSelectionTimeoutMS=2000)

        mydb = client["cyhy"]

        myfirstcoll = mydb["requests"]

        # allcollections = mydb.list_collection_names()

        getAllData = myfirstcoll.find()

        for x in getAllData:
            allAgency = x["_id"]
            agencyNames.append(allAgency)
            # allIPS is a list of all ip and subnets
            allIPS = x["networks"]

            agencyInfo[allAgency] = allIPS

            # theAgency = x['acronym']
    except OperationFailure as e:
        logging.error(f"There was a problem connecting to the database {e}")
    except ServerSelectionTimeoutError as err:
        logging.error(f"The cyhy db connection was not avalible.{err}")

    return agencyInfo, agencyNames


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


class InfoForm(FlaskForm):
    """Create web form to choose an agency from the cyhyDB."""

    # cyhybastionConn()
    cust = SelectField("Choose Agency", choices=cyhyGet()[1])
    submit = SubmitField("Submit")
