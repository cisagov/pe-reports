"""Create all api enpoints"""

# Standard Python Libraries
from typing import List, Any, Union, Dict
from datetime import datetime, timedelta
import json
import requests
import logging
import re
import asyncio
from io import TextIOWrapper
import csv
import pandas as pd
import codecs

# Third party imports
from fastapi import (
    APIRouter,
    FastAPI,
    Body,
    Depends,
    HTTPException,
    status,
    Security,
    File,
    UploadFile,
)

from fastapi.responses import ORJSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.api_key import APIKeyQuery, APIKeyCookie, APIKeyHeader, APIKey
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.contrib.auth.models import User
from django.db import transaction
from django.db import DataError
from django.contrib import messages
from uuid import UUID


from starlette.status import HTTP_403_FORBIDDEN
from jose import jwt, exceptions
from decouple import config

# cisagov Libraries
from home.models import CyhyDbAssets
from home.models import SubDomains
from home.models import Organizations
from home.models import VwBreachcomp
from home.models import VwBreachcompCredsbydate
from home.models import VwCidrs
from home.models import VwOrgsAttacksurface
from home.models import VwBreachcompBreachdetails
from home.models import WasTrackerCustomerdata


from .models import apiUser
from . import schemas

LOGGER = logging.getLogger(__name__)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

api_router = APIRouter()


ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
ALGORITHM = "HS256"
JWT_SECRET_KEY = config("JWT_SECRET_KEY")  # should be kept secret
JWT_REFRESH_SECRET_KEY = config("JWT_REFRESH_SECRET_KEY")  # should be kept secret

API_KEY_NAME = "access_token"
COOKIE_DOMAIN = "localtest.me"

# TODO following api_key_query was left intentionally for future development
#   to pass query to api call see issue#
# api_key_query = APIKeyQuery(name=API_KEY_NAME, auto_error=False)
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


def create_access_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    """Create access token"""
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt


def create_refresh_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    """Create a refresh token"""
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(
            minutes=REFRESH_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt


def userinfo(theuser):
    """Get all users in a list."""
    user_record = list(User.objects.filter(username=f"{theuser}"))

    if user_record:
        for u in user_record:
            return u.id


async def userapiTokenUpdate(expiredaccessToken, user_refresh, theapiKey, user_id):
    """When api apiKey is expired a new key is created
    and updated in the database."""
    theusername = ""
    user_record = list(User.objects.filter(id=f"{user_id}"))
    # user_record = User.objects.get(id=user_id)

    for u in user_record:
        theusername = u.username
        theuserid = u.id
    LOGGER.info(f"The username is {theusername} with a user of {theuserid}")

    updateapiuseraccessToken = apiUser.objects.get(apiKey=expiredaccessToken)
    # updateapiuserrefreshToken = apiUser.objects.get(refresh_token=expiredrefreshToken)

    updateapiuseraccessToken.apiKey = f"{create_access_token(theusername)}"
    # updateapiuserrefreshToken.refresh_token = f"{create_refresh_token(theusername)}"
    # LOGGER.info(updateapiuseraccessToken.apiKey)

    updateapiuseraccessToken.save(update_fields=["apiKey"])
    # updateapiuserrefreshToken.save(update_fields=['refresh_token'])
    LOGGER.info(
        f"The user api key and refresh token have been updated from: {theapiKey} to: {updateapiuseraccessToken.apiKey}."
    )


async def userapiTokenverify(theapiKey):
    """Check to see if api key is expired."""
    tokenRecords = list(apiUser.objects.filter(apiKey=theapiKey))
    user_key = ""
    user_refresh = ""
    user_id = ""

    for u in tokenRecords:
        user_refresh = u.refresh_token
        user_key = u.apiKey
        user_id = u.id
    # LOGGER.info(f'The user key is {user_key}')
    # LOGGER.info(f'The user refresh key is {user_refresh}')
    LOGGER.info(f"the token being verified at verify {theapiKey}")

    try:
        jwt.decode(
            theapiKey,
            config("JWT_REFRESH_SECRET_KEY"),
            algorithms=ALGORITHM,
            options={"verify_signature": False},
        )
        LOGGER.info(f"The api key was alright {theapiKey}")

    except exceptions.JWTError as e:
        LOGGER.warning("The access token has expired and will be updated")
        await userapiTokenUpdate(user_key, user_refresh, theapiKey, user_id)


async def get_api_key(
    # api_key_query: str = Security(api_key_query),
    api_key_header: str = Security(api_key_header),
    # api_key_cookie: str = Security(api_key_cookie),
):
    """Get api key from header."""

    if api_key_header != "":
        return api_key_header

    else:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials"
        )


def upload_was_data(dict):
    """Delete all data and replace with the data from the file that is getting uploaded."""
    print("Got to upload was data")
    if WasTrackerCustomerdata.objects.exists():
        LOGGER.info("There was data that was deleted from the WAS table.")
        WasTrackerCustomerdata.objects.all().delete()

    for row in dict:
        # Fix boolean columns
        if row["elections"] == "1.0":
            row["elections"] = True
        elif row["elections"] == "":
            row["elections"] = False
        if row["fceb"] == "1.0":
            row["fceb"] = True
        elif row["fceb"] == "":
            row["fceb"] = False
        if row["special_report"] == "1.0":
            row["special_report"] = True
        elif row["special_report"] == "":
            row["special_report"] = False

        wasCustomer = WasTrackerCustomerdata(
            tag=row["tag"],
            customer_name=row["customer_name"],
            testing_sector=row["testing_sector"],
            ci_type=row["ci_type"],
            jira_ticket=row["jira_ticket"],
            ticket=row["ticket"],
            next_scheduled=row["next_scheduled"],
            last_scanned=row["last_scanned"],
            frequency=row["frequency"],
            comments_notes=row["comments_notes"],
            was_report_poc=row["was_report_poc"],
            was_report_email=row["was_report_email"],
            onboarding_date=row["onboarding_date"],
            no_of_web_apps=row["no_of_web_apps"],
            no_web_apps_last_updated=row["no_web_apps_last_updated"],
            elections=row["elections"],
            fceb=row["fceb"],
            special_report=row["special_report"],
            report_password=row["report_password"],
            child_tags=row["child_tags"],
        )
        try:
            wasCustomer.save()
            print(f"saved {row}")

        except DataError as e:
            LOGGER.error("There is an issue with the data type %s", e)


# def api_key_auth(api_key: str = Depends(oauth2_scheme)):
#     if api_key not in api_keys:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Forbidden"
#         )


@api_router.post(
    "/orgs",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.Organization],
    tags=["List of all Organizations"],
)
def read_orgs(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all organizations."""
    orgs = Organizations.objects.all()

    # orgs_df = pd.DataFrame(orgs)

    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return orgs
    except:
        LOGGER.info("API key expired please try again")


@api_router.post(
    "/subdomains",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.SubDomainBase],
    tags=["List of all Subdomains"],
)
def read_sub_domain(
    tokens: dict = Depends(get_api_key),
):
    """API endpoint to get all organizations."""
    # count = SubDomains.objects.all().count()
    # print(f'The count is {count}')
    # finalList = []
    # chunk_size = 1000
    # for i in range(0, count, chunk_size):
    #     records = list(SubDomains.objects.all()[i:i+chunk_size])
    #     for record in records:
    #         finalList.append(record)
    subs = list(SubDomains.objects.all()[:99999])

    # orgs_df = pd.DataFrame(orgs)

    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return subs
    except:
        LOGGER.info("API key expired please try again")


@api_router.post(
    "/breachcomp",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.VwBreachcomp],
    tags=["List all breaches"],
)
def read_breachcomp(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all breaches."""
    breachInfo = list(VwBreachcomp.objects.all())
    print(breachInfo)

    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return breachInfo
    except:
        LOGGER.info("API key expired please try again")


@api_router.post(
    "/breachcomp_credsbydate",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.VwBreachcompCredsbydate],
    tags=["List all breaches by date"],
)
def read_breachcomp_credsbydate(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all breach creds by date."""
    breachcomp_dateInfo = list(VwBreachcompCredsbydate.objects.all())

    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return breachcomp_dateInfo
    except:
        LOGGER.info("API key expired please try again")


@api_router.post(
    "/orgs_attacksurface",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.VwOrgsAttacksurface],
    tags=["Get asset counts for an organization"],
)
def read_orgs_attacksurface(
    data: schemas.VwOrgsAttacksurfaceInput, tokens: dict = Depends(get_api_key)
):
    """Get asset counts for an organization attack surfaces."""
    print(data.organizations_uid)
    attackSurfaceInfo = list(
        VwOrgsAttacksurface.objects.filter(organizations_uid=data.organizations_uid)
    )

    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return attackSurfaceInfo
    except:
        LOGGER.info("API key expired please try again")


@api_router.post(
    "/cyhy_db_asset",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.CyhyDbAssets],
    tags=["Get cyhy assets"],
)
def read_cyhy_db_asset(
    data: schemas.CyhyDbAssetsInput, tokens: dict = Depends(get_api_key)
):
    """Get Query cyhy assets."""
    print(data.org_id)
    cyhyAssets = list(CyhyDbAssets.objects.filter(org_id=data.org_id))

    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return cyhyAssets
    except:
        LOGGER.info("API key expired please try again")


@api_router.post(
    "/cidrs",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.Cidrs],
    tags=["List of all CIDRS"],
)
def read_cidrs(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all CIDRS."""
    orgs = list(VwCidrs.objects.all())

    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return orgs
    except:
        LOGGER.info("API key expired please try again")


@api_router.post(
    "/breachdetails",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.VwBreachDetails],
    tags=["List of all Breach Details"],
)
def read_breachdetails(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all CIDRS."""
    breachDetails = list(VwBreachcompBreachdetails.objects.all())

    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return breachDetails
    except:
        LOGGER.info("API key expired please try again")


@api_router.post("/get_key", tags=["Get user api keys"])
def read_get_key(data: schemas.UserAPI):
    """API endpoint to get api by submitting refresh token."""
    user_key = ""
    userkey = list(apiUser.objects.filter(refresh_token=data.refresh_token))
    LOGGER.info(f"The input data requested was ***********{data.refresh_token[-10:]}")

    for u in userkey:
        user_key = u.apiKey
    return user_key


# @api_router.post("/testingUsers",
#                 tags=["List of user id"])
# def read_users(data: schemas.UserAuth):
#     user = userinfo(data.username)
#
#     # user = list(User.objects.filter(username='cduhn75'))
#     if user is None:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="User with this name does exist"
#         )
#     return userinfo(data.username)


# @api_router.get("/secure_endpoint", tags=["test"])
# async def get_open_api_endpoint(api_key: APIKey = Depends(get_api_key)):
#     print(api_key)
#     response = "How cool is this?"
#     return response


@api_router.post(
    "/signup",
    summary="Create api key and access token on user",
    tags=["Sign-up to add api_key and access token to user"],
)
def create_user(data: schemas.UserAuth):
    # querying database to check if user already exist
    user = userinfo(data.username)

    # TODO put logging statement here.
    print(f"The user id is {user}\n")
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this username does not exist",
        )

    theNewUser = apiUser(
        apiKey=create_access_token(data.username),
        user_id=user,
        refresh_token=create_refresh_token(data.username),
    )
    apiUser.save(theNewUser)
    return theNewUser


# @api_router.get("/items/")
# async def read_items(token: str=Depends(oauth2_scheme)):
#     return {"token": token}


@api_router.post(
    "/was_upload", dependencies=[Depends(get_api_key)], tags=["Upload WAS csv file"]
)
def upload(tokens: dict = Depends(get_api_key), file: UploadFile = File(...)):
    """Upload csv file from WAS"""

    if not tokens:
        return {"message": "No api key was submitted"}

    if not file.filename.endswith("csv"):
        raise HTTPException(400, detail="Invalid document type")
    
    # f = TextIOWrapper(file.file)

    dict_reader = csv.DictReader(codecs.iterdecode(file.file, 'utf-8'))
    col_names = dict_reader.fieldnames
    col_names = set(col_names)
    data_dict = list(dict_reader)

    required_columns = [
        "tag",
        "customer_name",
        "testing_sector",	
        "ci_type",
        "ticket",
        "next_scheduled",
        "last_scanned",
        "frequency",
        "comments_notes",
        "was_report_poc",
        "was_report_email",
        "onboarding_date",
        "no_of_web_apps",
    ]

    try:
        # Check that all the required column names are present
        if all(item in col_names for item in required_columns):
            print("column names are all correct")
            upload_was_data(data_dict)
            return {"message": "Successfully uploaded %s" % file.filename}
        else:
            for col in required_columns:
                if col in dict_reader:
                    pass
                else:
                    incorrect_col.append(col)
            raise HTTPException(
                400,
                detail="There was a missing or"
                " incorrect column in file,"
                " to columns %s" % incorrect_col,
            )

    except ValueError:
        return {
            "message": "There was an error uploading the file at %s." % incorrect_col
        }
    except ValidationError as e:
        return {"message": "There was an error uploading the file type at %s." % e}

    finally:
        file.file.close()


@api_router.post(
    "/was_info",
    dependencies=[Depends(get_api_key)],
    #  response_model=List[schemas.WASDataBase],
    tags=["List of all WAS data"],
)
def was_info(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all WAS data."""

    if not tokens:
        return {"message": "No api key was submitted"}
    try:
        was_data = list(WasTrackerCustomerdata.objects.all())
        userapiTokenverify(theapiKey=tokens)
        return was_data
    except:
        LOGGER.info("API key expired please try again")


@api_router.delete(
    "/was_info_delete/{tag}",
    dependencies=[Depends(get_api_key)],
    tags=["Delete WAS data"],
)
def was_info_delete(tag: str, tokens: dict = Depends(get_api_key)):
    """API endpoint to delete a record in database."""

    if not tokens:
        return {"message": "No api key was submitted"}

    was_data = WasTrackerCustomerdata.objects.get(tag=tag)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            was_data.delete()
            return {"deleted_tag": tag}
        except:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/was_info_create",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.WASDataBase],
    tags=["Create new WAS data"],
)
def was_info_create(customer: schemas.WASDataBase, tokens: dict = Depends(get_api_key)):
    """API endpoint to create a record in database."""

    if not tokens:
        return {"message": "No api key was submitted"}

    print("got to the endpoint")
    print(customer)
    was_customer = WasTrackerCustomerdata(**customer.dict())
    print(was_customer)

    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        was_customer.save()
        return {"saved_customer": was_customer}
    except:
        LOGGER.info("API key expired please try again")
        return {"message": "Failed to upload"}


@api_router.put(
    "/was_info_update/{tag}",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.WASDataBase],
    tags=["Update WAS data"],
)
@transaction.atomic
def was_info_update(
    tag: str, customer: schemas.WASDataBase, tokens: dict = Depends(get_api_key)
):
    """API endpoint to create a record in database."""
    if not tokens:
        return {"message": "No api key was submitted"}
    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        was_data = WasTrackerCustomerdata.objects.get(tag=tag)
        updated_data = {}
        for field, value in customer.dict(exclude_unset=True).items():
            print(f"the field is {field} and the value is {value}")
            if hasattr(was_data, field) and getattr(was_data, field) != value:
                setattr(was_data, field, value)
                updated_data[field] = value
        was_data.save()
        return {"message": "Record updated successfully.", "updated_data": updated_data}

        was_data.save()
        return {"updated_customer": was_data}
    except ObjectDoesNotExist:
        LOGGER.info("API key expired please try again")
