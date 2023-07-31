"""Create all api endpoints."""

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
    Request,
)

from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.api_key import APIKeyQuery, APIKeyCookie, APIKeyHeader, APIKey
from redis import asyncio as aioredis
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.contrib.auth.models import User
from django.conf import settings
from django.db.models import Q
from django.db import transaction
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
from home.models import MatVwOrgsAllIps
from home.models import VwOrgsAttacksurface
from home.models import VwBreachcompBreachdetails
from home.models import WasTrackerCustomerdata
from home.models import WeeklyStatuses
from home.models import CyhyPortScans
from dataAPI.tasks import get_vs_info
from dataAPI.tasks import get_ve_info

from dataAPI.tasks import (
    # D-Score Task Functions:
    get_dscore_vs_cert_info,
    get_dscore_vs_mail_info,
    get_dscore_pe_ip_info,
    get_dscore_pe_domain_info,
    get_dscore_was_webapp_info,
    get_fceb_status_info,
    # I-Score Task Functions:
    get_iscore_vs_vuln_info,
    get_iscore_vs_vuln_prev_info,
    get_iscore_pe_vuln_info,
    get_iscore_pe_cred_info,
    get_iscore_pe_breach_info,
    get_iscore_pe_darkweb_info,
    get_iscore_pe_protocol_info,
    get_iscore_was_vuln_info,
    get_iscore_was_vuln_prev_info,
    get_kev_list_info,
    # Misc. Score-Related Task Functions:
    get_xs_stakeholders_info,
    get_s_stakeholders_info,
    get_m_stakeholders_info,
    get_l_stakeholders_info,
    get_xl_stakeholders_info,
)

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


limiter = Limiter(key_func=get_remote_address, default_limits=["5 per minute"])


async def default_identifier(request):
    return request.headers.get("X-Real-IP", request.client.host)


@api_router.on_event("startup")
async def startup():
    redis = aioredis.from_url(
        settings.CELERY_RESULT_BACKEND, encoding="utf-8", decode_responses=True
    )
    await FastAPILimiter.init(redis, identifier=default_identifier)


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
        userapiTokenUpdate(user_key, user_refresh, theapiKey, user_id)


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
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.Organization],
    tags=["List of all Organizations"],
)
def read_orgs(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all organizations."""
    orgs = list(Organizations.objects.all())

    if tokens:

        # LOGGER.info(f"The api key submitted {tokens}")
        try:

            userapiTokenverify(theapiKey=tokens)
            return orgs
        except:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/fetch_weekly_statuses",
    dependencies=[Depends(get_api_key)],
    # response_model=List[schemas.WeeklyStatuses],
    tags=["List of all Weekly Statuses"],
)
def read_weekly_statuses(tokens: dict = Depends(get_api_key)):
    """API endpoint to get weekly statuses."""

    current_date = datetime.now()
    days_to_week_end = (4 - current_date.weekday()) % 7
    week_ending_date = current_date + timedelta(days=days_to_week_end)
    statuses = list(WeeklyStatuses.objects.filter(week_ending=week_ending_date))

    #    if tokens:
    # LOGGER.info(f"The api key submitted {tokens}")
    try:
        #        userapiTokenverify(theapiKey=tokens)
        return statuses
    except:
        LOGGER.info("API key expired please try again")


#   else:
#       return {'message': "No api key was submitted"}


@api_router.post(
    "/fetch_user_weekly_statuses/",
    dependencies=[Depends(get_api_key)],
    # response_model=List[schemas.WeeklyStatuses],
    tags=["List of user Weekly Status"],
)
def read_user_weekly_statuses(
    data: schemas.UserStatuses, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get a user weekly statuses."""

    current_date = datetime.now()
    days_to_week_end = (4 - current_date.weekday()) % 7
    week_ending_date = current_date + timedelta(days=days_to_week_end)
    statuses = list(
        WeeklyStatuses.objects.filter(
            week_ending=week_ending_date, user_status=data.user_fname
        )
    )

    # LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return statuses
    except:
        LOGGER.info("API key expired please try again")


@api_router.post(
    "/subdomains/{root_domain_uid}",
    dependencies=[Depends(get_api_key)],
    # response_model=List[schemas.SubDomainBase],
    tags=["List of all Subdomains"],
)
def read_sub_domain(root_domain_uid: str, tokens: dict = Depends(get_api_key)):
    """API endpoint to get all organizations."""
    # count = SubDomains.objects.all().count()
    # print(f'The count is {count}')
    # finalList = []
    # chunk_size = 1000
    # for i in range(0, count, chunk_size):
    #     records = list(SubDomains.objects.all()[i:i+chunk_size])
    #     for record in records:
    #         finalList.append(record)
    # subs = list(SubDomains.objects.all()[:999])
    subs = list(SubDomains.objects.filter(root_domain_uid=root_domain_uid))

    # orgs_df = pd.DataFrame(orgs)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            print("Got to subdomains try")
            userapiTokenverify(theapiKey=tokens)
            return subs
        except:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/breachcomp",
    dependencies=[Depends(get_api_key)],
    # response_model=List[schemas.VwBreachcomp],
    tags=["List all breaches"],
)
def read_breachcomp(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all breaches."""
    breachInfo = list(VwBreachcomp.objects.all())
    print(breachInfo)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            return breachInfo
        except:
            LOGGER.info("API key expired please try again")

    else:
        return {"message": "No api key was submitted"}


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
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            return breachcomp_dateInfo
        except:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


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
    if tokens:

        try:
            userapiTokenverify(theapiKey=tokens)
            return attackSurfaceInfo
        except:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


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
    if tokens:

        try:
            userapiTokenverify(theapiKey=tokens)
            return cyhyAssets
        except:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/cidrs",
    dependencies=[Depends(get_api_key)],
    # response_model=List[schemas.Cidrs],
    tags=["List of all CIDRS"],
)
def read_cidrs(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all CIDRS."""
    cidrs = list(VwCidrs.objects.all())

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:

        try:
            userapiTokenverify(theapiKey=tokens)
            return cidrs
        except:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


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
    if tokens:

        try:
            userapiTokenverify(theapiKey=tokens)
            return breachDetails
        except:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post("/get_key", tags=["Get user api keys"])
def read_get_key(data: schemas.UserAPI):
    """API endpoint to get api by submitting refresh token."""
    user_key = ""
    userkey = list(apiUser.objects.filter(refresh_token=data.refresh_token))
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

    dict_reader = csv.DictReader(codecs.iterdecode(file.file, "utf-8"))
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
    "/ve_info",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.TaskResponse,
    tags=["List of all VE data"],
)
def ve_info(ip_address: List[str], tokens: dict = Depends(get_api_key)):
    """API endpoint to get all WAS data."""
    print(ip_address)

    # orgs_df = pd.DataFrame(orgs)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        task = get_ve_info.delay(ip_address)
        return {"task_id": task.id, "status": "Processing"}
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/ve_info/task/{task_id}",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.veTaskResponse,
    tags=["Check task VE status"],
)
async def get_ve_task_status(task_id: str, tokens: dict = Depends(get_api_key)):
    task = get_ve_info.AsyncResult(task_id)

    if task.state == "SUCCESS":

        return {"task_id": task_id, "status": "Completed", "result": task.result}
    elif task.state == "PENDING":
        return {"task_id": task_id, "status": "Pending"}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "status": "Failed", "error": str(task.result)}
    else:
        return {"task_id": task_id, "status": task.state}


@api_router.post(
    "/vs_info",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.veTaskResponse,
    tags=["List of all VS data"],
)
def vs_info(cyhy_db_names: List[str], tokens: dict = Depends(get_api_key)):
    """API endpoint to get all WAS data."""
    print(cyhy_db_names)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        task = get_vs_info.delay(cyhy_db_names)
        return {"task_id": task.id, "status": "Processing"}
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/vs_info/task/{task_id}",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.TaskResponse,
    tags=["Check task status"],
)
async def get_task_status(task_id: str, tokens: dict = Depends(get_api_key)):
    task = get_vs_info.AsyncResult(task_id)

    if task.state == "SUCCESS":
        return {"task_id": task_id, "status": "Completed", "result": task.result}
    elif task.state == "PENDING":
        return {"task_id": task_id, "status": "Pending"}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "status": "Failed", "error": str(task.result)}
    else:
        return {"task_id": task_id, "status": task.state}


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
def was_info_create(request: Request, tokens: dict = Depends(get_api_key)):
    """API endpoint to create a record in database."""

    if not tokens:
        return {"message": "No api key was submitted"}

    print("got to the endpoint")

    LOGGER.info(f"The api key submitted {tokens}")
    try:
        # Get data header
        customer = json.loads(request.headers.get("x-data"))
        was_customer = WasTrackerCustomerdata.objects.create(**customer)
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
def was_info_update(tag: str, request: Request, tokens: dict = Depends(get_api_key)):
    """API endpoint to create a record in database."""
    if not tokens:
        return {"message": "No api key was submitted"}
    LOGGER.info(f"The api key submitted {tokens}")
    try:
        # Get customer header
        customer = json.loads(request.headers.get("x-data"))

        # Verify token
        userapiTokenverify(theapiKey=tokens)

        # Get WAS record based on tag
        was_data = WasTrackerCustomerdata.objects.get(tag=tag)
        updated_data = {}
        for field, value in customer.items():
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


@api_router.post(
    "/cyhy_port_scan",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.WASDataBase],
    tags=["Create new cyhy port scan data"],
)
def cyhy_port_scan_info_create(
    ports_scan_data: schemas.CyhyPortScans, tokens: dict = Depends(get_api_key)
):
    """API endpoint to create a record in database."""

    cyhy_ports = CyhyPortScans(**ports_scan_data.dict())

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:

        try:
            userapiTokenverify(theapiKey=tokens)
            cyhy_ports.save()
            return {"saved_customer": cyhy_ports}
        except:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.put(
    "/was_info_update/{cyhy_id}",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.WASDataBase],
    tags=["Update cyhy_port_scan data"],
)
@transaction.atomic
def cyhy_ports_scan_info_update(
    cyhy_id: str, org_scans: schemas.CyhyPortScans, tokens: dict = Depends(get_api_key)
):
    """API endpoint to update a record in database."""

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:

        try:
            userapiTokenverify(theapiKey=tokens)
            scan_data = CyhyPortScans.objects.get(cyhy_id=cyhy_id)
            updated_data = {}
            for field, value in org_scans.dict(exclude_unset=True).items():
                print(f"the field is {field} and the value is {value}")
                if hasattr(scan_data, field) and getattr(scan_data, field) != value:
                    setattr(scan_data, field, value)
                    updated_data[field] = value
            scan_data.save()
            return {
                "message": "Record updated successfully.",
                "updated_data": updated_data,
            }

        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# ---------- D-Score View Endpoints ----------
# --- Endpoint functions for vw_dscore_vs_cert view ---
@api_router.post(
    "/dscore_vs_cert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreVSCertTaskResp,
    tags=["Get all VS cert data needed for D-Score"],
)
def read_dscore_vs_cert(
    data: schemas.VwDscoreVSCertInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all VS cert data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_vs_cert_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/dscore_vs_cert/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreVSCertTaskResp,
    tags=["Check task status for D-Score VS cert view."],
)
async def get_dscore_vs_cert_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_dscore_vs_cert_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint functions for vw_dscore_vs_mail view ---
@api_router.post(
    "/dscore_vs_mail",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreVSMailTaskResp,
    tags=["Get all VS mail data needed for D-Score"],
)
def read_dscore_vs_mail(
    data: schemas.VwDscoreVSMailInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all VS mail data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_vs_mail_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/dscore_vs_mail/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreVSMailTaskResp,
    tags=["Check task status for D-Score VS mail view."],
)
async def get_dscore_vs_mail_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_dscore_vs_mail_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint functions for vw_dscore_pe_ip view ---
@api_router.post(
    "/dscore_pe_ip",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscorePEIpTaskResp,
    tags=["Get all PE IP data needed for D-Score"],
)
def read_dscore_pe_ip(
    data: schemas.VwDscorePEIpInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all PE IP data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_pe_ip_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/dscore_pe_ip/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscorePEIpTaskResp,
    tags=["Check task status for D-Score PE IP view."],
)
async def get_dscore_pe_ip_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_dscore_pe_ip_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint functions for vw_dscore_pe_domain view ---
@api_router.post(
    "/dscore_pe_domain",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscorePEDomainTaskResp,
    tags=["Get all PE domain data needed for D-Score"],
)
def read_dscore_pe_domain(
    data: schemas.VwDscorePEDomainInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all PE domain data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_pe_domain_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/dscore_pe_domain/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscorePEDomainTaskResp,
    tags=["Check task status for D-Score PE domain view."],
)
async def get_dscore_pe_domain_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_dscore_pe_domain_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint functions for vw_dscore_was_webapp view ---
@api_router.post(
    "/dscore_was_webapp",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreWASWebappTaskResp,
    tags=["Get all WAS webapp data needed for D-Score"],
)
def read_dscore_was_webapp(
    data: schemas.VwDscoreWASWebappInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all WAS webapp data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_was_webapp_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/dscore_was_webapp/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreWASWebappTaskResp,
    tags=["Check task status for D-Score WAS webapp view."],
)
async def get_dscore_was_webapp_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_dscore_was_webapp_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint function for FCEB status query (no view) ---
@api_router.post(
    "/fceb_status",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.FCEBStatusTaskResp,
    tags=["Get the FCEB status of a specified list of organizations."],
)
def read_fceb_status(
    data: schemas.FCEBStatusInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get the FCEB status of a specified list of organizations."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_fceb_status_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/fceb_status/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.FCEBStatusTaskResp,
    tags=["Check task status for FCEB status query."],
)
async def get_fceb_status_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_fceb_status_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# ---------- I-Score View Endpoints ----------
# --- Endpoint functions for vw_iscore_vs_vuln view ---
@api_router.post(
    "/iscore_vs_vuln",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreVSVulnTaskResp,
    tags=["Get all VS vuln data needed for I-Score"],
)
def read_iscore_vs_vuln(
    data: schemas.VwIscoreVSVulnInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all VS vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_vs_vuln_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_vs_vuln/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreVSVulnTaskResp,
    tags=["Check task status for I-Score VS vuln view."],
)
async def get_iscore_vs_vuln_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_vs_vuln_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint functions for vw_iscore_vs_vuln_prev view ---
@api_router.post(
    "/iscore_vs_vuln_prev",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreVSVulnPrevTaskResp,
    tags=["Get all previous VS vuln data needed for I-Score"],
)
def read_iscore_vs_vuln_prev(
    data: schemas.VwIscoreVSVulnPrevInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all previous VS vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_vs_vuln_prev_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_vs_vuln_prev/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreVSVulnPrevTaskResp,
    tags=["Check task status for I-Score previous VS vuln view."],
)
async def get_iscore_vs_vuln_prev_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_vs_vuln_prev_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint functions for vw_iscore_pe_vuln view ---
@api_router.post(
    "/iscore_pe_vuln",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEVulnTaskResp,
    tags=["Get all PE vuln data needed for I-Score"],
)
def read_iscore_pe_vuln(
    data: schemas.VwIscorePEVulnInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all PE vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_vuln_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_pe_vuln/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEVulnTaskResp,
    tags=["Check task status for I-Score PE vuln view."],
)
async def get_iscore_pe_vuln_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_pe_vuln_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint functions for vw_iscore_pe_cred view ---
@api_router.post(
    "/iscore_pe_cred",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePECredTaskResp,
    tags=["Get all PE cred data needed for I-Score"],
)
def read_iscore_pe_cred(
    data: schemas.VwIscorePECredInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all PE cred data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_cred_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_pe_cred/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePECredTaskResp,
    tags=["Check task status for I-Score PE cred view."],
)
async def get_iscore_pe_cred_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_pe_cred_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint functions for vw_iscore_pe_breach view ---
@api_router.post(
    "/iscore_pe_breach",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEBreachTaskResp,
    tags=["Get all PE breach data needed for I-Score"],
)
def read_iscore_pe_breach(
    data: schemas.VwIscorePEBreachInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all PE breach data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_breach_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_pe_breach/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEBreachTaskResp,
    tags=["Check task status for I-Score PE breach view."],
)
async def get_iscore_pe_breach_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_pe_breach_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint functions for vw_iscore_pe_darkweb view ---
@api_router.post(
    "/iscore_pe_darkweb",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEDarkwebTaskResp,
    tags=["Get all PE darkweb data needed for I-Score"],
)
def read_iscore_pe_darkweb(
    data: schemas.VwIscorePEDarkwebInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all PE darkweb data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_darkweb_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_pe_darkweb/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEDarkwebTaskResp,
    tags=["Check task status for I-Score PE darkweb view."],
)
async def get_iscore_pe_darkweb_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_pe_darkweb_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint functions for vw_iscore_pe_protocol view ---
@api_router.post(
    "/iscore_pe_protocol",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEProtocolTaskResp,
    tags=["Get all PE protocol data needed for I-Score"],
)
def read_iscore_pe_protocol(
    data: schemas.VwIscorePEProtocolInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all PE protocol data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_protocol_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_pe_protocol/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEProtocolTaskResp,
    tags=["Check task status for I-Score PE protocol view."],
)
async def get_iscore_pe_protocol_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_pe_protocol_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint functions for vw_iscore_was_vuln view ---
@api_router.post(
    "/iscore_was_vuln",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreWASVulnTaskResp,
    tags=["Get all WAS vuln data needed for I-Score"],
)
def read_iscore_was_vuln(
    data: schemas.VwIscoreWASVulnInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all WAS vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_was_vuln_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_was_vuln/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreWASVulnTaskResp,
    tags=["Check task status for I-Score WAS vuln view."],
)
async def get_iscore_was_vuln_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_was_vuln_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint functions for vw_iscore_was_vuln_prev view ---
@api_router.post(
    "/iscore_was_vuln_prev",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreWASVulnPrevTaskResp,
    tags=["Get all previous WAS vuln data needed for I-Score"],
)
def read_iscore_was_vuln_prev(
    data: schemas.VwIscoreWASVulnPrevInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all previous WAS vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_was_vuln_prev_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_was_vuln_prev/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreWASVulnPrevTaskResp,
    tags=["Check task status for I-Score previous WAS vuln view."],
)
async def get_iscore_was_vuln_prev_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_was_vuln_prev_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint function for KEV list query (no view) ---
@api_router.post(
    "/kev_list",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.KEVListTaskResp,
    tags=["Get list of all KEVs."],
)
def read_fceb_status(tokens: dict = Depends(get_api_key)):
    """API endpoint to get list of all KEVs."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_kev_list_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/kev_list/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.KEVListTaskResp,
    tags=["Check task status for KEV list query."],
)
async def get_kev_list_task_status(task_id: str, tokens: dict = Depends(get_api_key)):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_kev_list_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# ---------- Misc. Score View Endpoints ----------
# --- Endpoint function for XS stakeholder list query ---
@api_router.post(
    "/xs_stakeholders",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Get list of all XS stakeholders."],
)
def read_xs_stakeholders(tokens: dict = Depends(get_api_key)):
    """API endpoint to get list of all XS stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_xs_stakeholders_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/xs_stakeholders/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Check task status for XS stakeholder query."],
)
async def get_xs_stakeholders_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_xs_stakeholders_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint function for S stakeholder list query ---
@api_router.post(
    "/s_stakeholders",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Get list of all S stakeholders."],
)
def read_s_stakeholders(tokens: dict = Depends(get_api_key)):
    """API endpoint to get list of all S stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_s_stakeholders_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/s_stakeholders/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Check task status for S stakeholder query."],
)
async def get_s_stakeholders_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_s_stakeholders_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint function for M stakeholder list query ---
@api_router.post(
    "/m_stakeholders",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Get list of all M stakeholders."],
)
def read_m_stakeholders(tokens: dict = Depends(get_api_key)):
    """API endpoint to get list of all M stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_m_stakeholders_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/m_stakeholders/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Check task status for M stakeholder query."],
)
async def get_m_stakeholders_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_m_stakeholders_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint function for L stakeholder list query ---
@api_router.post(
    "/l_stakeholders",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Get list of all L stakeholders."],
)
def read_l_stakeholders(tokens: dict = Depends(get_api_key)):
    """API endpoint to get list of all L stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_l_stakeholders_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/l_stakeholders/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Check task status for L stakeholder query."],
)
async def get_l_stakeholders_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_l_stakeholders_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint function for XL stakeholder list query ---
@api_router.post(
    "/xl_stakeholders",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Get list of all XL stakeholders."],
)
def read_xl_stakeholders(tokens: dict = Depends(get_api_key)):
    """API endpoint to get list of all XL stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_xl_stakeholders_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/xl_stakeholders/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Check task status for XL stakeholder query."],
)
async def get_xl_stakeholders_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_xl_stakeholders_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}
