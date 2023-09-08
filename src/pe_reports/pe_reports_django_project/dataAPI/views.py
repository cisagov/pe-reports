"""Create all api enpoints."""

# Standard Python Libraries
import csv
from datetime import datetime, timedelta
from io import TextIOWrapper
import logging
from typing import Any, List, Union

# Third-Party Libraries
from dataAPI.tasks import *

from decouple import config
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import transaction
from django.db.models import F
import numpy as np
import socket

# Third party imports
from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Security,
    status,
    UploadFile,
)
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.api_key import APIKeyHeader
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from home.models import *
from jose import exceptions, jwt
from redis import asyncio as aioredis
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.status import HTTP_403_FORBIDDEN

from . import schemas
from .models import apiUser

# from pe_reports.helpers import ip_passthrough


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
    """Return default identifier."""
    return request.headers.get("X-Real-IP", request.client.host)


@api_router.on_event("startup")
async def startup():
    """Start up Redis."""
    redis = aioredis.from_url(
        settings.CELERY_RESULT_BACKEND, encoding="utf-8", decode_responses=True
    )
    await FastAPILimiter.init(redis, identifier=default_identifier)


def create_access_token(
    subject: Union[str, Any], expires_delta: timedelta = None
) -> str:
    """Create access token."""
    if expires_delta is not None:
        expires_date = datetime.utcnow() + expires_delta
    else:
        expires_date = datetime.utcnow() + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {"exp": expires_date, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt


def create_refresh_token(
    subject: Union[str, Any], expires_delta: timedelta = None
) -> str:
    """Create a refresh token."""
    if expires_delta is not None:
        expires_date = datetime.utcnow() + expires_delta
    else:
        expires_date = datetime.utcnow() + timedelta(
            minutes=REFRESH_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {"exp": expires_date, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt


def userinfo(theuser):
    """Get all users in a list."""
    user_record = list(User.objects.filter(username=f"{theuser}"))

    if user_record:
        for u in user_record:
            return u.id


def userapiTokenUpdate(expiredaccessToken, user_refresh, theapiKey, user_id):
    """When api apiKey is expired a new key is created and updated in the database."""
    print(f"Got to update token {expiredaccessToken}")
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


def userapiTokenverify(theapiKey):
    """Check to see if api key is expired."""
    tokenRecords = list(apiUser.objects.filter(apiKey=theapiKey))
    user_key = ""
    user_refresh = ""
    user_id = ""

    for u in tokenRecords:
        user_refresh = u.refresh_token
        user_key = u.apiKey
        user_id = u.id
    LOGGER.info(f"The user key is {user_key}")
    LOGGER.info(f"The user refresh key is {user_refresh}")
    LOGGER.info(f"the token being verified at verify {theapiKey}")

    try:
        jwt.decode(
            theapiKey,
            config("JWT_REFRESH_SECRET_KEY"),
            algorithms=ALGORITHM,
            options={"verify_signature": False},
        )
        LOGGER.info(f"The api key was alright {theapiKey}")

    except exceptions.JWTError:
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


def process_item(item):
    """Process CSV rows."""
    # TODO: Replace with the code for what you wish to do with the row of data in the CSV.
    LOGGER.info("The item is %s" % item)
    print("The item is %s" % item)


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
    """Call API endpoint to get all organizations."""
    orgs = list(Organizations.objects.all())

    if tokens:

        # LOGGER.info(f"The api key submitted {tokens}")
        try:

            userapiTokenverify(theapiKey=tokens)
            return orgs
        except Exception:
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
    """Call API endpoint to get weekly statuses."""
    current_date = datetime.now()
    days_to_week_end = (4 - current_date.weekday()) % 7
    week_ending_date = current_date + timedelta(days=days_to_week_end)
    statuses = list(WeeklyStatuses.objects.filter(week_ending=week_ending_date))

    # LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return statuses
    except Exception:
        LOGGER.info("API key expired please try again")


@api_router.post(
    "/fetch_user_weekly_statuses/",
    dependencies=[Depends(get_api_key)],
    # response_model=List[schemas.WeeklyStatuses],
    tags=["List of user Weekly Status"],
)
def read_user_weekly_statuses(
    data: schemas.UserStatuses, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get a user weekly statuses."""
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
    except Exception:
        LOGGER.info("API key expired please try again")


@api_router.post(
    "/subdomains/{root_domain_uid}",
    dependencies=[Depends(get_api_key)],
    # response_model=List[schemas.SubDomainBase],
    tags=["List of all Subdomains"],
)
def read_sub_domain(root_domain_uid: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all organizations."""
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
        except Exception:
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
    """Call API endpoint to get all breaches."""
    breachInfo = list(VwBreachcomp.objects.all())
    print(breachInfo)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            return breachInfo
        except Exception:
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
    """Call API endpoint to get all breach creds by date."""
    breachcomp_dateInfo = list(VwBreachcompCredsbydate.objects.all())

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            return breachcomp_dateInfo
        except Exception:
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
        except Exception:
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
        except Exception:
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
    """Call API endpoint to get all CIDRS."""
    cidrs = list(VwCidrs.objects.all())

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:

        try:
            userapiTokenverify(theapiKey=tokens)
            return cidrs
        except Exception:
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
    """Call API endpoint to get all CIDRS."""
    breachDetails = list(VwBreachcompBreachdetails.objects.all())

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:

        try:
            userapiTokenverify(theapiKey=tokens)
            return breachDetails
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post("/get_key", tags=["Get user api keys"])
def read_get_key(data: schemas.UserAPI):
    """Call API endpoint to get api by submitting refresh token."""
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
    """Create an API User."""
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
def upload(file: UploadFile = File(...)):
    """Upload csv file from WAS."""
    f = TextIOWrapper(file.file)

    dict_reader = csv.DictReader(f)
    # dict_reader = dict_reader.fieldnames
    # dict_reader = set(dict_reader)
    col_names = dict_reader.fieldnames
    if col_names is None:
        raise HTTPException(400, detail="The CSV file does not have headers")

    col_names_set: set[str] = set(col_names)

    required_columns = [
        "org",
        "org_code",
        "root_domain",
        "exec_url",
        "aliases",
        "premium",
        "demo",
    ]
    # Check needed columns exist
    incorrect_col = []
    testtheList = [i for i in required_columns if i in col_names_set]

    try:
        if not file.filename.endswith("csv"):

            raise HTTPException(400, detail="Invalid document type")

        if len(testtheList) == len(col_names):

            for row, item in enumerate(dict_reader, start=1):
                process_item(item)
            return {"message": "Successfully uploaded %s" % file.filename}
        else:
            for col in required_columns:
                if col in col_names:
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
    "/rva_info",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.TaskResponse,
    tags=["List of all VE data"],
)
def rva_info(ip_address: List[str], tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all WAS data."""
    print(ip_address)

    # orgs_df = pd.DataFrame(orgs)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        task = get_rva_info.delay(ip_address)
        return {"task_id": task.id, "status": "Processing"}
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/rva_info/task/{task_id}",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.veTaskResponse,
    tags=["Check task VE status"],
)
async def get_rva_task_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Get RVA task status."""
    task = get_rva_info.AsyncResult(task_id)

    if task.state == "SUCCESS":

        return {"task_id": task_id, "status": "Completed", "result": task.result}
    elif task.state == "PENDING":
        return {"task_id": task_id, "status": "Pending"}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "status": "Failed", "error": str(task.result)}
    else:
        return {"task_id": task_id, "status": task.state}


@api_router.post(
    "/ve_info",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.TaskResponse,
    tags=["List of all VE data"],
)
def ve_info(ip_address: List[str], tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all WAS data."""
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
    """Get VE task status."""
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
    """Call API endpoint to get all WAS data."""
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
    """Get VS info task status."""
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
    response_model=List[schemas.WASDataBase],
    tags=["List of all WAS data"],
)
def was_info(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all WAS data."""
    was_data = list(WasTrackerCustomerdata.objects.all())

    # orgs_df = pd.DataFrame(orgs)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            return was_data
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.delete(
    "/was_info_delete/{tag}",
    dependencies=[Depends(get_api_key)],
    tags=["Delete WAS data"],
)
def was_info_delete(tag: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to delete a record in database."""
    was_data = WasTrackerCustomerdata.objects.get(tag=tag)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:

        try:
            userapiTokenverify(theapiKey=tokens)
            was_data.delete()
            return {"deleted_tag": tag}
        except Exception:
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
    """Call API endpoint to create a record in database."""
    was_customer = WasTrackerCustomerdata(**customer.dict())

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:

        try:
            userapiTokenverify(theapiKey=tokens)
            was_customer.save()
            return {"saved_customer": was_customer}
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


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
    """Call API endpoint to create a record in database."""
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:

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
            return {
                "message": "Record updated successfully.",
                "updated_data": updated_data,
            }

        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/cyhy_port_scan",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.WASDataBase],
    tags=["Create new cyhy port scan data"],
)
def cyhy_port_scan_info_create(
    ports_scan_data: schemas.CyhyPortScans, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to create a record in database."""
    cyhy_ports = CyhyPortScans(**ports_scan_data.dict())

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:

        try:
            userapiTokenverify(theapiKey=tokens)
            cyhy_ports.save()
            return {"saved_customer": cyhy_ports}
        except Exception:
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
    """Call API endpoint to update a record in database."""
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


# ---------- D-Score View Endpoints, Issue 571 ----------
# --- Endpoint functions for vw_dscore_vs_cert view ---
@api_router.post(
    "/dscore_vs_cert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreVSCertTaskResp,
    tags=["Get all VS cert data needed for D-Score"],
)
def read_dscore_vs_cert(
    data: schemas.GenInputOrgUIDList, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all VS cert data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_vs_cert_info.delay(data.org_uid_list)
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
    """Call API endpoint to get status of dscore_vs_cert task."""
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
    data: schemas.GenInputOrgUIDList, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all VS mail data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_vs_mail_info.delay(data.org_uid_list)
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
    """Call API endpoint to get status of dscore_vs_mail task."""
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
    data: schemas.GenInputOrgUIDList, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE IP data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_pe_ip_info.delay(data.org_uid_list)
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
    """Call API endpoint to get status of dscore_pe_ip task."""
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
    data: schemas.GenInputOrgUIDList, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE domain data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_pe_domain_info.delay(data.org_uid_list)
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
    """Call API endpoint to get status of dscore_pe_domain task."""
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
    data: schemas.GenInputOrgUIDList, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all WAS webapp data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_was_webapp_info.delay(data.org_uid_list)
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
    """Call API endpoint to get status of dscore_was_webapp task."""
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
    data: schemas.GenInputOrgUIDList, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get the FCEB status of a specified list of organizations."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_fceb_status_info.delay(data.org_uid_list)
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
    """Call API endpoint to get status of fceb_status task."""
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


# ---------- I-Score View Endpoints, Issue 570 ----------
# --- Endpoint functions for vw_iscore_vs_vuln view ---
@api_router.post(
    "/iscore_vs_vuln",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreVSVulnTaskResp,
    tags=["Get all VS vuln data needed for I-Score"],
)
def read_iscore_vs_vuln(
    data: schemas.GenInputOrgUIDList, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all VS vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_vs_vuln_info.delay(data.org_uid_list)
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
    """Call API endpoint to get status of iscore_vs_vuln task."""
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
    data: schemas.GenInputOrgUIDListDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all previous VS vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_vs_vuln_prev_info.delay(
                data.org_uid_list, data.start_date, data.end_date
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
    """Call API endpoint to get status of iscore_vs_vuln_prev task."""
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
    data: schemas.GenInputOrgUIDListDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_vuln_info.delay(
                data.org_uid_list, data.start_date, data.end_date
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
    """Call API endpoint to get status of iscore_pe_vuln task."""
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
    data: schemas.GenInputOrgUIDListDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE cred data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_cred_info.delay(
                data.org_uid_list, data.start_date, data.end_date
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
    """Call API endpoint to get status of iscore_pe_cred task."""
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
    data: schemas.GenInputOrgUIDListDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE breach data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_breach_info.delay(
                data.org_uid_list, data.start_date, data.end_date
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
    """Call API endpoint to get status of iscore_pe_breach task."""
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
    data: schemas.GenInputOrgUIDListDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE darkweb data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_darkweb_info.delay(
                data.org_uid_list, data.start_date, data.end_date
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
    """Call API endpoint to get status of iscore_pe_darkweb task."""
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
    data: schemas.GenInputOrgUIDListDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE protocol data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_protocol_info.delay(
                data.org_uid_list, data.start_date, data.end_date
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
    """Call API endpoint to get status of iscore_pe_protocol task."""
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
    data: schemas.GenInputOrgUIDListDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all WAS vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_was_vuln_info.delay(
                data.org_uid_list, data.start_date, data.end_date
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
    """Call API endpoint to get status of iscore_was_vuln task."""
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
    data: schemas.GenInputOrgUIDListDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all previous WAS vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_was_vuln_prev_info.delay(
                data.org_uid_list, data.start_date, data.end_date
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
    """Call API endpoint to get status of iscore_vas_vuln_prev task."""
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
def read_kev_list(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get list of all KEVs."""
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
    """Call API endpoint to get status of kev_list task."""
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
    """Call API endpoint to get list of all XS stakeholders."""
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
    """Call API endpoint to get status of xs_stakeholders task."""
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
    """Call API endpoint to get list of all S stakeholders."""
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
    """Call API endpoint to get status of s_stakeholders task."""
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
    """Call API endpoint to get list of all M stakeholders."""
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
    """Call API endpoint to get status of m_stakeholders task."""
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
    """Call API endpoint to get list of all L stakeholders."""
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
    """Call API endpoint to get status of l_stakeholders task."""
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
    """Call API endpoint to get list of all XL stakeholders."""
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
    """Call API endpoint to get status of xl_stakeholders task."""
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


@api_router.post(
    "/data_source/{source_name}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    # response_model=schemas.DataSource,
    tags=["Get Data_source table"],
)
def get_data_source(source_name: str, tokens: dict = Depends(get_api_key)):
    """Get data source API endpoint."""
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            try:
                datas = list(DataSource.objects.filter(name=f"{source_name}"))
                print(datas)
                return datas[0]
            except ValidationError:
                return {"message": "Data source does not exist"}

        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# data_source_uid: str,request: Request, tokens: dict = Depends(get_api_key)


@api_router.put(
    "/update_last_viewed/{data_source_uid}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    tags=["Update last viewed data"],
)
@transaction.atomic
def update_last_viewed(data_source_uid: str, tokens: dict = Depends(get_api_key)):
    """Update last viewed column in the datasource table."""
    if not tokens:
        return {"message": "No api key was submitted"}
    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        try:
            data_source = DataSource.objects.get(data_source_uid=data_source_uid)
        except ValidationError:
            return {"message": "Data source does not exist"}
        data_source.last_run = datetime.today().strftime("%Y-%m-%d")
        data_source.save()
        return {"message": "Record updated successfully."}
    except ObjectDoesNotExist:
        LOGGER.info("API key expired please try again")


# --- execute_ips(), Issue 559 ---
@api_router.post(
    "/ips_insert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.IpsInsertTaskResp,
    tags=["Insert new ip records into the ips table"],
)
def ips_insert(data: schemas.IpsInsertInput, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to insert new ip records into the ips table."""
    # Convert list of input models to list of dictionaries
    new_ips = [dict(input_dict) for input_dict in data.new_ips]
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = ips_insert_task.delay(new_ips)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/ips_insert/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.IpsInsertTaskResp,
    tags=["Check task status for ips_insert endpoint task."],
)
async def ips_insert_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of ips_insert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = ips_insert_task.AsyncResult(task_id)
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


# --- query_all_subs(), Issue 560 ---
@api_router.post(
    "/sub_domains_table",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.SubDomainTableTaskResp,
    tags=["Get all data from the sub_domains table"],
)
def sub_domains_table(
    data: schemas.SubDomainTableInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all data from the sub_domains table."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = sub_domains_table_task.delay(data.page, data.per_page)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/sub_domains_table/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.SubDomainTableTaskResp,
    tags=["Check task status for sub_domains_table endpoint task."],
)
async def sub_domains_table_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of sub_domains_table task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = sub_domains_table_task.AsyncResult(task_id)
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


# --- query_domMasq_alerts(), Issue 562 ---
@api_router.get(
    "/domain_alerts_by_org_date",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.DomainAlertsTable],
    tags=["Get all domain_alerts table data for the specified org_uid and date range."],
)
def domain_alerts_by_org_date(
    data: schemas.GenInputOrgUIDDateRange, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all domain_alerts table data for the specified org_uid and date range."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            domain_alerts_by_org_date_data = list(
                DomainAlerts.objects.filter(
                    organizations_uid=data.org_uid,
                    date__range=[data.start_date, data.end_date],
                ).values()
            )
            # Convert uuids to strings
            for row in domain_alerts_by_org_date_data:
                row["domain_alert_uid"] = convert_uuid_to_string(
                    row["domain_alert_uid"]
                )
                row["sub_domain_uid_id"] = convert_uuid_to_string(
                    row["sub_domain_uid_id"]
                )
                row["data_source_uid_id"] = convert_uuid_to_string(
                    row["data_source_uid_id"]
                )
                row["organizations_uid"] = convert_uuid_to_string(
                    row["organizations_uid"]
                )
                row["date"] = convert_date_to_string(row["date"])
            return domain_alerts_by_org_date_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_domMasq(), Issue 563 ---
@api_router.get(
    "/domain_permu_by_org_date",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.DomainPermuTable],
    tags=[
        "Get all domain_permutations table data for the specified org_uid and date range."
    ],
)
def domain_permu_by_org_date(
    data: schemas.GenInputOrgUIDDateRange, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all domain_permutations table data for the specified org_uid and date range."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            domain_permu_by_org_date_data = list(
                DomainPermutations.objects.filter(
                    organizations_uid=data.org_uid,
                    date_active__range=[data.start_date, data.end_date],
                ).values()
            )
            # Convert uuids to strings
            for row in domain_permu_by_org_date_data:
                row["suspected_domain_uid"] = convert_uuid_to_string(
                    row["suspected_domain_uid"]
                )
                row["organizations_uid_id"] = convert_uuid_to_string(
                    row["organizations_uid_id"]
                )
                row["date_observed"] = convert_date_to_string(row["date_observed"])
                row["data_source_uid_id"] = convert_uuid_to_string(
                    row["data_source_uid_id"]
                )
                row["sub_domain_uid_id"] = convert_uuid_to_string(
                    row["sub_domain_uid_id"]
                )
                row["date_active"] = convert_date_to_string(row["date_active"])
            return domain_permu_by_org_date_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- insert_roots(), Issue 564 ---
@api_router.put(
    "/root_domains_insert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert list of root domains for the specified org."],
)
def root_domains_insert(
    data: schemas.RootDomainsInsertInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to insert list of root domains for the specified org."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, go through and insert domains
            insert_count = 0
            for domain in data.domain_list:
                # Check if record already exists
                domain_results = RootDomains.objects.filter(
                    root_domain=domain,
                    organizations_uid=data.org_dict["organizations_uid"],
                )
                if not domain_results.exists():
                    # If not, insert new record
                    curr_org_uid = Organizations.objects.get(
                        organizations_uid=data.org_dict["organizations_uid"]
                    )
                    try:
                        ip = socket.gethostbyname(domain)
                    except Exception:
                        ip = np.nan
                    pe_data_source_uid = DataSource.objects.get(name="P&E")
                    RootDomains.objects.create(
                        organizations_uid=curr_org_uid,
                        root_domain=domain,
                        ip_address=ip,
                        data_source_uid=pe_data_source_uid,
                        enumerate_subs=True,
                    )
                    insert_count += 1
            return (
                str(insert_count)
                + " domains were inserted into root_domains table for "
                + data.org_dict["cyhy_db_name"]
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_orgs_contacts(), Issue 601 ---
@api_router.get(
    "/orgs_report_on_contacts",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.OrgsReportOnContacts],
    tags=["Get all contact data for orgs where report_on is true."],
)
def orgs_report_on_contacts(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all contact data for orgs where report_on is true."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            orgs_report_on_contacts_data = list(
                CyhyContacts.objects.filter(
                    org_id__in=Organizations.objects.filter(report_on=True).values(
                        "cyhy_db_name"
                    )
                ).values("email", "contact_type", "org_id")
            )
            return orgs_report_on_contacts_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_org_assets_count_past(), Issue 603 ---
@api_router.get(
    "/past_asset_counts_by_org",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.RSSTable],
    tags=["Get all RSS data for the specified org_uid and date."],
)
def past_asset_counts_by_org(
    data: schemas.GenInputOrgUIDDateSingle, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all RSS data for the specified org_uid and date."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            past_asset_counts_by_org_data = list(
                ReportSummaryStats.objects.filter(
                    organizations_uid=data.org_uid, end_date=data.date
                ).values()
            )
            # Convert uuids to strings
            for row in past_asset_counts_by_org_data:
                row["report_uid"] = convert_uuid_to_string(row["report_uid"])
                row["organizations_uid_id"] = convert_uuid_to_string(
                    row["organizations_uid_id"]
                )
                row["start_date"] = convert_date_to_string(row["start_date"])
                row["end_date"] = convert_date_to_string(row["end_date"])
            return past_asset_counts_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_org_assets_count(), Issue 604 ---
@api_router.get(
    "/asset_counts_by_org",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.AssetCountsByOrg],
    tags=["Get attacksurface data for the specified org_uid."],
)
def asset_counts_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get attacksurface data for the specified org_uid."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            asset_counts_by_org_data = list(
                VwOrgsAttacksurface.objects.filter(
                    organizations_uid=data.org_uid
                ).values(
                    "organizations_uid",
                    "cyhy_db_name",
                    "num_root_domain",
                    "num_sub_domain",
                    "num_ips",
                    "num_ports",
                    "num_cidrs",
                    "num_ports_protocols",
                    "num_software",
                    "num_foreign_ips",
                )
            )
            # Convert uuids to strings
            for row in asset_counts_by_org_data:
                row["organizations_uid"] = convert_uuid_to_string(
                    row["organizations_uid"]
                )
            return asset_counts_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_new_orgs(), Issue 605 ---
@api_router.get(
    "/orgs_report_on_false",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.OrgsTable],
    tags=["Get all data for organizations where report on is false."],
)
def orgs_report_on_false(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all data for organizations where report on is false."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            orgs_report_on_false_data = list(
                Organizations.objects.filter(report_on=False).values()
            )
            # Convert uuids to strings
            for row in orgs_report_on_false_data:
                row["organizations_uid"] = convert_uuid_to_string(
                    row["organizations_uid"]
                )
                row["org_type_uid_id"] = convert_uuid_to_string(row["org_type_uid_id"])
                row["date_first_reported"] = convert_date_to_string(
                    row["date_first_reported"]
                )
                row["parent_org_uid_id"] = convert_uuid_to_string(
                    row["parent_org_uid_id"]
                )
                row["cyhy_period_start"] = convert_date_to_string(
                    row["cyhy_period_start"]
                )
            return orgs_report_on_false_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- set_org_to_report_on(), Issue 606 ---
@api_router.get(
    "/orgs_set_report_on",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.OrgsTable],
    tags=["Set report_on to true for the specified organization."],
)
def orgs_set_report_on(
    data: schemas.OrgsSetReportOnInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to set report_on to true for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            specified_org = list(
                Organizations.objects.filter(cyhy_db_name=data.cyhy_db_name).values()
            )
            if len(specified_org) != 0:
                # If org exists, update fields
                Organizations.objects.filter(cyhy_db_name=data.cyhy_db_name).update(
                    report_on=True, premium_report=data.premium, demo=False
                )
                # Convert uuids to strings
                for row in specified_org:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["org_type_uid_id"] = convert_uuid_to_string(
                        row["org_type_uid_id"]
                    )
                    row["date_first_reported"] = convert_date_to_string(
                        row["date_first_reported"]
                    )
                    row["parent_org_uid_id"] = convert_uuid_to_string(
                        row["parent_org_uid_id"]
                    )
                    row["cyhy_period_start"] = convert_date_to_string(
                        row["cyhy_period_start"]
                    )
                return specified_org
            else:
                # Otherwise, return empty
                LOGGER.error("No org found for that cyhy id")
                return [
                    {
                        "organizations_uid": "NOT FOUND",
                        "name": "",
                        "cyhy_db_name": "",
                        "org_type_uid_id": "",
                        "report_on": False,
                        "password": "",
                        "date_first_reported": "",
                        "parent_org_uid_id": "",
                        "premium_report": False,
                        "agency_type": "",
                        "demo": False,
                        "scorecard": False,
                        "fceb": False,
                        "receives_cyhy_report": False,
                        "receives_bod_report": False,
                        "receives_cybex_report": False,
                        "run_scans": False,
                        "is_parent": False,
                        "ignore_roll_up": True,
                        "retired": True,
                        "cyhy_period_start": "",
                        "fceb_child": False,
                        "election": False,
                        "scorecard_child": False,
                    }
                ]
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- set_org_to_demo(), Issue 607 ---
@api_router.get(
    "/orgs_set_demo",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.OrgsTable],
    tags=["Set demo to true for the specified organization."],
)
def orgs_set_demo(
    data: schemas.OrgsSetReportOnInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to set demo to true for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            specified_org = list(
                Organizations.objects.filter(cyhy_db_name=data.cyhy_db_name).values()
            )
            if len(specified_org) != 0:
                # If org exists, update fields
                Organizations.objects.filter(cyhy_db_name=data.cyhy_db_name).update(
                    report_on=False, premium_report=data.premium, demo=True
                )
                # Convert uuids to strings
                for row in specified_org:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["org_type_uid_id"] = convert_uuid_to_string(
                        row["org_type_uid_id"]
                    )
                    row["date_first_reported"] = convert_date_to_string(
                        row["date_first_reported"]
                    )
                    row["parent_org_uid_id"] = convert_uuid_to_string(
                        row["parent_org_uid_id"]
                    )
                    row["cyhy_period_start"] = convert_date_to_string(
                        row["cyhy_period_start"]
                    )
                return specified_org
            else:
                # Otherwise, return empty
                LOGGER.error("No org found for that cyhy id")
                return [
                    {
                        "organizations_uid": "NOT FOUND",
                        "name": "",
                        "cyhy_db_name": "",
                        "org_type_uid_id": "",
                        "report_on": False,
                        "password": "",
                        "date_first_reported": "",
                        "parent_org_uid_id": "",
                        "premium_report": False,
                        "agency_type": "",
                        "demo": False,
                        "scorecard": False,
                        "fceb": False,
                        "receives_cyhy_report": False,
                        "receives_bod_report": False,
                        "receives_cybex_report": False,
                        "run_scans": False,
                        "is_parent": False,
                        "ignore_roll_up": True,
                        "retired": True,
                        "cyhy_period_start": "",
                        "fceb_child": False,
                        "election": False,
                        "scorecard_child": False,
                    }
                ]
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_cyhy_assets(), Issue 608 ---
@api_router.get(
    "/cyhy_assets_by_org",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.CyhyDbAssetsByOrg],
    tags=["Get all cyhy assets for the specified organization."],
)
def cyhy_assets_by_org(
    data: schemas.GenInputOrgCyhyNameSingle, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all cyhy assets for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            cyhy_assets_by_org_data = list(
                CyhyDbAssets.objects.filter(
                    org_id=data.org_cyhy_name, currently_in_cyhy=True
                ).values()
            )
            # Convert uuids to strings
            for row in cyhy_assets_by_org_data:
                row["field_id"] = convert_uuid_to_string(row["field_id"])
                row["first_seen"] = convert_date_to_string(row["first_seen"])
                row["last_seen"] = convert_date_to_string(row["last_seen"])
            return cyhy_assets_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_cidrs_and_ips(), Issue 610 ---
@api_router.get(
    "/cidrs_ips_by_org",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.CidrsIpsByOrg],
    tags=["Get all CIDRs and IPs for the specified organization."],
)
def cidrs_ips_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all CIDRs and IPs for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            cidr_ip_data = list(
                Cidrs.objects.filter(organizations_uid=data.org_uid).values(
                    ip=F("network")
                )
            )
            sub_root_ip_data = list(
                VwIpsSubRootOrgInfo.objects.filter(
                    organizations_uid=data.org_uid, origin_cidr__isnull=True
                ).values("ip")
            )
            cidrs_ips_by_org_data = cidr_ip_data + sub_root_ip_data
            return cidrs_ips_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_ips(), Issue 611 ---
@api_router.get(
    "/ips_by_org",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.IpsByOrg,
    tags=["Get all IPs for the specified organization."],
)
def ips_by_org(data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)):
    """API endpoint to get all IPs for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            cidr_ip_data = list(
                VwIpsCidrOrgInfo.objects.filter(
                    organizations_uid=data.org_uid, origin_cidr__isnull=False
                ).values("ip")
            )
            sub_root_ip_data = list(
                VwIpsSubRootOrgInfo.objects.filter(
                    organizations_uid=data.org_uid
                ).values("ip")
            )
            return {"cidr_ip_data": cidr_ip_data, "sub_root_ip_data": sub_root_ip_data}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_extra_ips(), Issue 612 ---
@api_router.get(
    "/extra_ips_by_org",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.ExtraIpsByOrg],
    tags=["Get all extra IPs for the specified organization."],
)
def extra_ips_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all extra IPs for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            extra_ips_by_org_data = list(
                VwIpsSubRootOrgInfo.objects.filter(
                    organizations_uid=data.org_uid, origin_cidr__isnull=True
                ).values("ip_hash", "ip")
            )
            return extra_ips_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- set_from_cidr(), Issue 616 ---
@api_router.post(
    "/ips_update_from_cidr",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.IpsUpdateFromCidrTaskResp,
    tags=["Set from_cidr to True for any IPs that have an origin CIDR."],
)
def ips_update_from_cidr(tokens: dict = Depends(get_api_key)):
    """API endpoint to set from_cidr to True for any IPs that have an origin CIDR."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = ips_update_from_cidr_task.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/ips_update_from_cidr/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.IpsUpdateFromCidrTaskResp,
    tags=["Check task status for ips_update_from_cidr endpoint task."],
)
async def ips_update_from_cidr_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """API endpoint to check status of ips_update_from_cidr endpoint task."""
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = ips_update_from_cidr_task.AsyncResult(task_id)
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


# --- query_cidrs_by_org(), Issue 618 ---
@api_router.get(
    "/cidrs_by_org",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.CidrsByOrg],
    tags=["Get all CIDRs for a specified organization."],
)
def cidrs_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all CIDRs for a specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            cidrs_by_org_data = list(
                Cidrs.objects.filter(
                    organizations_uid=data.org_uid, current=True
                ).values()
            )

            # Convert uuids to strings
            for row in cidrs_by_org_data:
                row["cidr_uid"] = convert_uuid_to_string(row["cidr_uid"])
                row["organizations_uid_id"] = convert_uuid_to_string(
                    row["organizations_uid_id"]
                )
                row["data_source_uid_id"] = convert_uuid_to_string(
                    row["data_source_uid_id"]
                )
                row["first_seen"] = convert_date_to_string(row["first_seen"])
                row["last_seen"] = convert_date_to_string(row["last_seen"])
            return cidrs_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_ports_protocols(), Issue 619 ---
@api_router.get(
    "/ports_protocols_by_org",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.PortsProtocolsByOrg],
    tags=["Get all distinct ports/protocols for a specified organization."],
)
def ports_protocols_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all distinct ports/protocols for a specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            ports_protocols_by_org_data = list(
                ShodanAssets.objects.filter(organizations_uid=data.org_uid)
                .values("port", "protocol")
                .distinct()
            )
            return ports_protocols_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_software(), Issue 620 ---
@api_router.get(
    "/software_by_org",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.SoftwareByOrg],
    tags=["Get all distinct software products for a specified organization."],
)
def software_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all distinct software products for a specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            software_by_org_data = list(
                ShodanAssets.objects.filter(
                    organizations_uid=data.org_uid, product__isnull=False
                )
                .values("product")
                .distinct()
            )
            return software_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_foreign_IPs(), Issue 621 ---
@api_router.get(
    "/foreign_ips_by_org",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.ForeignIpsByOrg],
    tags=["Get all foreign IPs for a specified organization."],
)
def foreign_ips_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all foreign IPs for a specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            foreign_ips_by_org_data = list(
                ShodanAssets.objects.filter(
                    organizations_uid=data.org_uid, country_code__isnull=False
                )
                .exclude(country_code="US")
                .values()
            )
            # Convert uuids to strings
            for row in foreign_ips_by_org_data:
                row["shodan_asset_uid"] = convert_uuid_to_string(
                    row["shodan_asset_uid"]
                )
                row["organizations_uid_id"] = convert_uuid_to_string(
                    row["organizations_uid_id"]
                )
                row["timestamp"] = convert_date_to_string(row["timestamp"])
                row["data_source_uid_id"] = convert_uuid_to_string(
                    row["data_source_uid_id"]
                )
            return foreign_ips_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_roots(), Issue 622 ---
@api_router.get(
    "/root_domains_by_org",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.RootDomainsByOrg],
    tags=["Get all root domains for a specified organization."],
)
def root_domains_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """API endpoint to get all root domains for a specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            root_domains_by_org_data = list(
                RootDomains.objects.filter(
                    organizations_uid=data.org_uid, enumerate_subs=True
                ).values()
            )
            # Convert uuids to strings
            for row in root_domains_by_org_data:
                row["root_domain_uid"] = convert_uuid_to_string(row["root_domain_uid"])
            return root_domains_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- execute_scorecard(), Issue 632 ---
@api_router.put(
    "/rss_insert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    # response_model=schemas.RSSInsertTaskResp,
    tags=["Insert an organization's record into the report_summary_stats table"],
)
def rss_insert(data: schemas.RSSInsertInput, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to insert an organization's record into the report_summary_stats table."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid
            # Get Organizations.organization_uid object for the specified org
            specified_org_uid = Organizations.objects.get(
                organizations_uid=data.organizations_uid
            )
            # Insert new record. If record already exists, update that record
            ReportSummaryStats.objects.update_or_create(
                organizations_uid=specified_org_uid,
                start_date=data.start_date,
                defaults={
                    "organizations_uid": specified_org_uid,
                    "start_date": data.start_date,
                    "end_date": data.end_date,
                    "ip_count": data.ip_count,
                    "root_count": data.root_count,
                    "sub_count": data.sub_count,
                    "ports_count": data.ports_count,
                    "creds_count": data.creds_count,
                    "breach_count": data.breach_count,
                    "cred_password_count": data.cred_password_count,
                    "domain_alert_count": data.domain_alert_count,
                    "suspected_domain_count": data.suspected_domain_count,
                    "insecure_port_count": data.insecure_port_count,
                    "verified_vuln_count": data.verified_vuln_count,
                    "suspected_vuln_count": data.suspected_vuln_count,
                    "suspected_vuln_addrs_count": data.suspected_vuln_addrs_count,
                    "threat_actor_count": data.threat_actor_count,
                    "dark_web_alerts_count": data.dark_web_alerts_count,
                    "dark_web_mentions_count": data.dark_web_mentions_count,
                    "dark_web_executive_alerts_count": data.dark_web_executive_alerts_count,
                    "dark_web_asset_alerts_count": data.dark_web_asset_alerts_count,
                    "pe_number_score": data.pe_number_score,
                    "pe_letter_grade": data.pe_letter_grade,
                },
            )
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_subs(), Issue 633 ---
@api_router.get(
    "/sub_domains_by_org",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.SubDomainTable],
    tags=["Get all sub domains for a specified organization."],
)
def sub_domains_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all sub domains for a specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            sub_domains_by_org_data = list(
                SubDomains.objects.filter(
                    root_domain_uid__organizations_uid=data.org_uid
                ).values()
            )
            # Convert uuids to strings
            for row in sub_domains_by_org_data:
                row["sub_domain_uid"] = convert_uuid_to_string(row["sub_domain_uid"])
                row["root_domain_uid_id"] = convert_uuid_to_string(
                    row["root_domain_uid_id"]
                )
                row["data_source_uid_id"] = convert_uuid_to_string(
                    row["data_source_uid_id"]
                )
                row["dns_record_uid_id"] = convert_uuid_to_string(
                    row["dns_record_uid_id"]
                )
                row["first_seen"] = convert_date_to_string(row["first_seen"])
                row["last_seen"] = convert_date_to_string(row["last_seen"])
            return sub_domains_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_previous_period(), Issue 634 ---
@api_router.get(
    "/rss_prev_period",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.RSSPrevPeriod],
    tags=[
        "Get previous report period report_summary_stats data for the specified organization"
    ],
)
def rss_prev_period(
    data: schemas.RSSPrevPeriodInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get previous period report_summary_stats data for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid
            # Make query
            rss_prev_period_data = list(
                ReportSummaryStats.objects.filter(
                    organizations_uid=data.org_uid, end_date=data.prev_end_date
                ).values(
                    "ip_count",
                    "root_count",
                    "sub_count",
                    "cred_password_count",
                    "suspected_vuln_addrs_count",
                    "suspected_vuln_count",
                    "insecure_port_count",
                    "threat_actor_count",
                )
            )
            return rss_prev_period_data
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- pescore_hist_domain_alert(), Issue 635 ---
@api_router.post(
    "/pescore_hist_domain_alert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistDomainAlertTaskResp,
    tags=["Get all historical domain alert data for PE score."],
)
def pescore_hist_domain_alert(
    data: schemas.GenInputDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get the PE score domain alert data for a specified time period."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = pescore_hist_domain_alert_task.delay(data.start_date, data.end_date)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/pescore_hist_domain_alert/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistDomainAlertTaskResp,
    tags=["Check task status for pescore_hist_domain_alert endpoint task."],
)
async def pescore_hist_domain_alert_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get status of pescore_hist_domain_alert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = pescore_hist_domain_alert_task.AsyncResult(task_id)
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


# --- pescore_hist_darkweb_alert(), Issue 635 ---
@api_router.post(
    "/pescore_hist_darkweb_alert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistDarkwebAlertTaskResp,
    tags=["Get all historical darkweb alert data for PE score."],
)
def pescore_hist_darkweb_alert(
    data: schemas.GenInputDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get the PE score dark web alert data for a specified time period."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = pescore_hist_darkweb_alert_task.delay(data.start_date, data.end_date)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/pescore_hist_darkweb_alert/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistDarkwebAlertTaskResp,
    tags=["Check task status for pescore_hist_darkweb_alert endpoint task."],
)
async def pescore_hist_darkweb_alert_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get status of pescore_hist_darkweb_alert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = pescore_hist_darkweb_alert_task.AsyncResult(task_id)
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


# --- pescore_hist_darkweb_ment(), Issue 635 ---
@api_router.post(
    "/pescore_hist_darkweb_ment",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistDarkwebMentTaskResp,
    tags=["Get all historical darkweb mention data for PE score."],
)
def pescore_hist_darkweb_ment(
    data: schemas.GenInputDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get the PE score dark web mention data for a specified time period."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = pescore_hist_darkweb_ment_task.delay(data.start_date, data.end_date)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/pescore_hist_darkweb_ment/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistDarkwebMentTaskResp,
    tags=["Check task status for pescore_hist_darkweb_ment endpoint task."],
)
async def pescore_hist_darkweb_ment_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get status of pescore_hist_darkweb_ment task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = pescore_hist_darkweb_ment_task.AsyncResult(task_id)
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


# --- pescore_hist_cred(), Issue 635 ---
@api_router.post(
    "/pescore_hist_cred",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistCredTaskResp,
    tags=["Get all historical credential data for PE score."],
)
def pescore_hist_cred(
    data: schemas.GenInputDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get the PE score credential data for a specified time period."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = pescore_hist_cred_task.delay(data.start_date, data.end_date)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/pescore_hist_cred/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistCredTaskResp,
    tags=["Check task status for pescore_hist_cred endpoint task."],
)
async def pescore_hist_cred_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of pescore_hist_cred task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = pescore_hist_cred_task.AsyncResult(task_id)
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


# --- pescore_base_metrics(), Issue 635 ---
@api_router.post(
    "/pescore_base_metrics",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreBaseMetricsTaskResp,
    tags=["Get all base metric data for PE score."],
)
def pescore_base_metrics(
    data: schemas.GenInputDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get the PE score base metric data for a specified time period."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = pescore_base_metrics_task.delay(data.start_date, data.end_date)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/pescore_base_metrics/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreBaseMetricsTaskResp,
    tags=["Check task status for pescore_base_metrics endpoint task."],
)
async def pescore_base_metrics_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get status of pescore_base_metrics task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = pescore_base_metrics_task.AsyncResult(task_id)
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


# --- get_new_cves_list(), Issue 636 ---
@api_router.get(
    "/pescore_check_new_cve",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.VwPEScoreCheckNewCVE],
    tags=["Get any detected CVEs that aren't in the cve_info table yet."],
)
def pescore_check_new_cve(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get any detected CVEs that aren't in the cve_info table yet."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            pescore_check_new_cve_data = list(
                VwPEScoreCheckNewCVE.objects.values("cve_name")
            )
            return pescore_check_new_cve_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- upsert_new_cves(), Issue 637 ---
@api_router.post(
    "/cve_info_insert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CVEInfoInsertTaskResp,
    tags=["Upsert new CVEs into the cve_info table"],
)
def cve_info_insert(
    data: schemas.CVEInfoInsertInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to insert new CVEs into the cve_info table."""
    # Convert list of input models to list of dictionaries
    new_cves = [dict(input_dict) for input_dict in data.new_cves]
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = cve_info_insert_task.delay(new_cves)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/cve_info_insert/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CVEInfoInsertTaskResp,
    tags=["Check task status for cve_info_insert endpoint task."],
)
async def cve_info_insert_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of cve_info_insert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = cve_info_insert_task.AsyncResult(task_id)
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


# --- get_intelx_breaches(), Issue 641 ---
@api_router.post(
    "/cred_breach_intelx",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CredBreachIntelXTaskResp,
    tags=["Get IntelX credential breaches"],
)
def cred_breach_intelx(
    data: schemas.CredBreachIntelXInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get IntelX credential breaches."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = cred_breach_intelx_task.delay(data.source_uid)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/cred_breach_intelx/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CredBreachIntelXTaskResp,
    tags=["Check task status for cred_breach_intelx endpoint task."],
)
async def cred_breach_intelx_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of cred_breach_intelx task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = cred_breach_intelx_task.AsyncResult(task_id)
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


# --- insert_sixgill_topCVEs(), Issue 657
@api_router.put(
    "/top_cves_insert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert multiple records into the top_cves table."],
)
def top_cves_insert(
    data: schemas.TopCVEsInsertInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to insert multiple records into the top_cves table."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # If API key valid, proceed
            create_ct = 0
            for record in data.insert_data:
                # convert to dict
                record = dict(record)
                curr_source_inst = DataSource.objects.get(
                    data_source_uid=record["data_source_uid"]
                )
                # Insert each row of data, on conflict do nothing
                try:
                    TopCves.objects.get(cve_id=record["cve_id"], date=record["date"])
                    # If record already exists, do nothing
                except TopCves.DoesNotExist:
                    # Otherwise, create new record
                    TopCves.objects.create(
                        top_cves_uid=uuid.uuid1(),
                        cve_id=record["cve_id"],
                        dynamic_rating=record["dynamic_rating"],
                        nvd_base_score=record["nvd_base_score"],
                        date=record["date"],
                        summary=record["summary"],
                        data_source_uid=curr_source_inst,
                    )
                    create_ct += 1
            return str(create_ct) + " records created in the top_cves table"
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- execute_dnsmonitor_data(), Issue 659
@api_router.put(
    "/domain_permu_insert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert multiple DNSMonitor records into the domain_permutations table."],
)
def domain_permu_insert(
    data: schemas.DomainPermuInsertInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to insert multiple DNSMonitor records into the domain_permutations table."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # If API key valid, proceed
            create_ct = 0
            update_ct = 0
            for record in data.insert_data:
                # convert to dict
                record = dict(record)
                curr_org_inst = Organizations.objects.get(
                    organizations_uid=record["organizations_uid"]
                )
                curr_source_inst = DataSource.objects.get(
                    data_source_uid=record["data_source_uid"]
                )
                # Insert each row of data, on conflict update existing
                try:
                    DomainPermutations.objects.get(
                        organizations_uid=curr_org_inst,
                        domain_permutation=record["domain_permutation"],
                    )
                    # If record already exists, update
                    DomainPermutations.objects.filter(
                        organizations_uid=curr_org_inst,
                        domain_permutation=record["domain_permutation"],
                    ).update(
                        ipv4=record["ipv4"],
                        ipv6=record["ipv6"],
                        date_observed=record["date_observed"],
                        mail_server=record["mail_server"],
                        name_server=record["name_server"],
                        sub_domain_uid=record["sub_domain_uid"],
                        data_source_uid=curr_source_inst,
                    )
                    update_ct += 1
                except DomainPermutations.DoesNotExist:
                    # Otherwise, create new record
                    DomainPermutations.objects.create(
                        organizations_uid=curr_org_inst,
                        domain_permutation=record["domain_permutation"],
                        ipv4=record["ipv4"],
                        ipv6=record["ipv6"],
                        date_observed=record["date_observed"],
                        mail_server=record["mail_server"],
                        name_server=record["name_server"],
                        sub_domain_uid=record["sub_domain_uid"],
                        data_source_uid=curr_source_inst,
                    )
                    create_ct += 1
            return (
                "DNSMonitor records in the domain_permutations table: "
                + str(create_ct)
                + " created, "
                + str(update_ct)
                + " updated"
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- execute_dnsmonitor_alert_data(), Issue 660
@api_router.put(
    "/domain_alerts_insert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert multiple DNSMonitor records into the domain_alerts table."],
)
def domain_alerts_insert(
    data: schemas.DomainAlertsInsertInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to insert multiple DNSMonitor records into the domain_alerts table."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # If API key valid, proceed
            create_ct = 0
            for record in data.insert_data:
                # convert to dict
                record = dict(record)
                curr_sub_inst = SubDomains.objects.get(
                    sub_domain_uid=record["sub_domain_uid"]
                )
                curr_source_inst = DataSource.objects.get(
                    data_source_uid=record["data_source_uid"]
                )
                # Insert each row of data, on conflict do nothing
                try:
                    DomainAlerts.objects.get(
                        alert_type=record["alert_type"],
                        sub_domain_uid=record["sub_domain_uid"],
                        date=record["date"],
                        new_value=record["new_value"],
                    )
                    # If record already exists, do nothing
                except DomainAlerts.DoesNotExist:
                    # Otherwise, create new record
                    DomainAlerts.objects.create(
                        domain_alert_uid=uuid.uuid1(),
                        organizations_uid=record["organizations_uid"],
                        sub_domain_uid=curr_sub_inst,
                        data_source_uid=curr_source_inst,
                        alert_type=record["alert_type"],
                        message=record["message"],
                        previous_value=record["previous_value"],
                        new_value=record["new_value"],
                        date=record["date"],
                    )
                    create_ct += 1
            return (
                str(create_ct)
                + " DNSMonitor records created in the domain_alerts table"
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- addRootdomain(), Issue 661 ---
@api_router.put(
    "/root_domains_single_insert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert a single root domain into the root_domains table."],
)
def root_domains_single_insert(
    data: schemas.RootDomainsSingleInsertInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to insert a single root domain into the root_domains table."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, insert root domain
            # Check if record already exists
            domain_results = RootDomains.objects.filter(
                root_domain=data.root_domain,
                organizations_uid=data.pe_org_uid,
                data_source_uid=data.source_uid,
            )
            if not domain_results.exists():
                # If not, insert new record
                curr_org_inst = Organizations.objects.get(
                    organizations_uid=data.pe_org_uid
                )
                curr_source_inst = DataSource.objects.get(
                    data_source_uid=data.source_uid
                )
                try:
                    ip = socket.gethostbyname(data.root_domain)
                except Exception:
                    ip = np.nan
                RootDomains.objects.create(
                    root_domain=data.root_domain,
                    organizations_uid=curr_org_inst,
                    data_source_uid=curr_source_inst,
                    ip_address=ip,
                )
                return (
                    "Root domain has been inserted into root_domains table for "
                    + data.org_name
                )
            return (
                "Root domain already exists in root_domains table for " + data.org_name
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- addSubdomain(), Issue 662 ---
@api_router.put(
    "/sub_domains_single_insert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert a single sub domain into the sub_domains table."],
)
def sub_domains_single_insert(
    data: schemas.SubDomainsSingleInsertInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to insert a single sub domain into the sub_domains table."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, proceed
            if data.root:
                # If sub domain is also a root domain
                curr_root = data.domain
            else:
                # If sub domain is not a root domain
                curr_root = data.domain.split(".")[-2]
                curr_root = ".".join(curr_root)
            curr_date = datetime.today().strftime("%Y-%m-%d")
            org_name = Organizations.objects.filter(
                organizations_uid=data.pe_org_uid
            ).values("cyhy_db_name")[0]["cyhy_db_name"]
            # Check if sub domain already exists in table
            sub_domain_results = SubDomains.objects.filter(
                sub_domain=data.domain,
                root_domain_uid__organizations_uid=data.pe_org_uid,
            )
            if not sub_domain_results.exists():
                # If not, insert new record
                # Get data_source instance of "findomain"
                findomain_inst = DataSource.objects.get(name="findomain")
                # Check if root domain already exists
                root_results = RootDomains.objects.filter(
                    organizations_uid=data.pe_org_uid, root_domain=curr_root
                )
                if not root_results.exists():
                    # If root domain does not exist, create a new record
                    RootDomains.objects.create(
                        organizations_uid=Organizations.objects.get(
                            organizations_uid=data.pe_org_uid
                        ),
                        root_domain=curr_root,
                        data_source_uid=findomain_inst,
                        enumerate_subs=False,
                    )
                # Get root_domains instance of specified root domain
                root_inst = RootDomains.objects.get(
                    organizations_uid=data.pe_org_uid, root_domain=curr_root
                )
                # Create new sub domain record
                SubDomains.objects.create(
                    sub_domain=data.domain,
                    root_domain_uid=root_inst,
                    data_source_uid=findomain_inst,
                    first_seen=curr_date,
                    last_seen=curr_date,
                    identified=False,
                )
                # Return status message
                return (
                    "Sub domain has been inserted into sub_domains table for "
                    + org_name
                )
            else:
                # If sub domain already exists, update last_seen and identified
                SubDomains.objects.filter(
                    sub_domain=data.domain,
                    root_domain_uid__organizations_uid=data.pe_org_uid,
                ).update(last_seen=curr_date, identified=False)
                # Return status message
                return (
                    "Sub domain record has been updated in the sub_domains table for "
                    + org_name
                )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- insert_intelx_breaches(), Issue 663 ---
@api_router.put(
    "/cred_breaches_intelx_insert",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert IntelX credential breaches into the credential_breaches table."],
)
def cred_breaches_intelx_insert(
    data: schemas.CredBreachesIntelxInsertInput, tokens: dict = Depends(get_api_key)
):
    """API endpoint to insert IntelX credential breaches into the credential_breaches table."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, insert intelx breach data
            insert_count = 0
            for row in data.breach_data:
                # Check if record already exists
                row_dict = row.__dict__
                breach_results = CredentialBreaches.objects.filter(
                    breach_name=row_dict["breach_name"]
                )
                if not breach_results.exists():
                    # If not, insert new record
                    curr_data_source_inst = DataSource.objects.get(
                        data_source_uid=row_dict["data_source_uid"]
                    )
                    CredentialBreaches.objects.create(
                        breach_name=row_dict["breach_name"],
                        description=row_dict["description"],
                        breach_date=row_dict["breach_date"],
                        added_date=row_dict["added_date"],
                        modified_date=row_dict["modified_date"],
                        password_included=row_dict["password_included"],
                        data_source_uid=curr_data_source_inst,
                    )
                    insert_count += 1
            return (
                str(insert_count)
                + " IntelX cred breach records were inserted into credential_breaches table"
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/pshtt_unscanned_domains",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.PshttDomainToRunTaskResp,
    tags=["List of subdomains to run through PSHTT"],
)
def get_unscanned_pshtt_domains(tokens: dict = Depends(get_api_key)):
    """Create API endpoint to get current domains that have not been run through pshtt recently."""
    # Check for API key

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        # Create task for query
        task = get_vw_pshtt_domains_to_run_info.delay()

        # Return the new task id w/ "Processing" status
        return {"task_id": task.id, "status": "Processing"}

    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/pshtt_unscanned_domains/task/{task_id}",
    dependencies=[Depends(get_api_key)],
    # , Depends(RateLimiter(times=200, seconds=60))
    response_model=schemas.PshttDomainToRunTaskResp,
    tags=["Check task status for endpoint."],
)
async def get_pshtt_domains_to_run_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Retrieve status of get_pshtt_domains_to_run task."""
    # Retrieve task status
    task = get_vw_pshtt_domains_to_run_info.AsyncResult(task_id)
    # Return appropriate message for status
    if task.state == "SUCCESS":
        return {"task_id": task_id, "status": "Completed", "result": task.result}
    elif task.state == "PENDING":
        return {"task_id": task_id, "status": "Pending"}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "status": "Failed", "error": str(task.result)}
    else:
        return {"task_id": task_id, "status": task.state}


@api_router.put(
    "/pshtt_result_update_or_insert",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.PshttDataBase],
    tags=["Update or insert PSHTT data"],
)
# @transaction.atomic
def pshtt_result_update_or_insert(
    # tag: str,
    data: schemas.PshttInsert,
    tokens: dict = Depends(get_api_key),
):
    """Create API endpoint to create a record in database."""
    if tokens:
        try:
            print(data.organizations_uid)
            userapiTokenverify(theapiKey=tokens)
            LOGGER.info(f"The api key submitted {tokens}")
            data_source_uid = DataSource.objects.get(name="Pshtt")
            organization_uid = Organizations.objects.get(
                organizations_uid=data.organizations_uid
            )
            sub_domain_uid = SubDomains.objects.get(sub_domain_uid=data.sub_domain_uid)

            # Get WAS record based on tag
            pshtt_object, created = PshttResults.objects.update_or_create(
                sub_domain_uid=data.sub_domain_uid,
                organizations_uid=data.organizations_uid,
                defaults={
                    "organizations_uid": organization_uid,
                    "sub_domain_uid": sub_domain_uid,
                    "data_source_uid": data_source_uid,
                    "sub_domain": data.sub_domain,
                    "date_scanned": data.date_scanned,
                    "base_domain": data.base_domain,
                    "base_domain_hsts_preloaded": data.base_domain_hsts_preloaded,
                    "canonical_url": data.canonical_url,
                    "defaults_to_https": data.defaults_to_https,
                    "domain": data.domain,
                    "domain_enforces_https": data.domain_enforces_https,
                    "domain_supports_https": data.domain_supports_https,
                    "domain_uses_strong_hsts": data.domain_uses_strong_hsts,
                    "downgrades_https": data.downgrades_https,
                    "htss": data.htss,
                    "hsts_entire_domain": data.hsts_entire_domain,
                    "hsts_header": data.hsts_header,
                    "hsts_max_age": data.hsts_max_age,
                    "hsts_preload_pending": data.hsts_preload_pending,
                    "hsts_preload_ready": data.hsts_preload_ready,
                    "hsts_preloaded": data.hsts_preloaded,
                    "https_bad_chain": data.https_bad_chain,
                    "https_bad_hostname": data.https_bad_hostname,
                    "https_cert_chain_length": data.https_cert_chain_length,
                    "https_client_auth_required": data.https_client_auth_required,
                    "https_custom_truststore_trusted": data.https_custom_truststore_trusted,
                    "https_expired_cert": data.https_expired_cert,
                    "https_full_connection": data.https_full_connection,
                    "https_live": data.https_live,
                    "https_probably_missing_intermediate_cert": data.https_probably_missing_intermediate_cert,
                    "https_publicly_trusted": data.https_publicly_trusted,
                    "https_self_signed_cert": data.https_self_signed_cert,
                    "https_leaf_cert_expiration_date": data.https_leaf_cert_expiration_date,
                    "https_leaf_cert_issuer": data.https_leaf_cert_issuer,
                    "https_leaf_cert_subject": data.https_leaf_cert_subject,
                    "https_root_cert_issuer": data.https_root_cert_issuer,
                    "ip": data.ip,
                    "live": data.live,
                    "notes": data.notes,
                    "redirect": data.redirect,
                    "redirect_to": data.redirect_to,
                    "server_header": data.server_header,
                    "server_version": data.server_version,
                    "strictly_forces_https": data.strictly_forces_https,
                    "unknown_error": data.unknown_error,
                    "valid_https": data.valid_https,
                    "ep_http_headers": data.ep_http_headers,
                    "ep_http_server_header": data.ep_http_server_header,
                    "ep_http_server_version": data.ep_http_server_version,
                    "ep_https_headers": data.ep_https_headers,
                    "ep_https_hsts_header": data.ep_https_hsts_header,
                    "ep_https_server_header": data.ep_https_server_header,
                    "ep_https_server_version": data.ep_https_server_version,
                    "ep_httpswww_headers": data.ep_httpswww_headers,
                    "ep_httpswww_hsts_header": data.ep_httpswww_hsts_header,
                    "ep_httpswww_server_header": data.ep_httpswww_server_header,
                    "ep_httpswww_server_version": data.ep_httpswww_server_version,
                    "ep_httpwww_headers": data.ep_httpwww_headers,
                    "ep_httpwww_server_header": data.ep_httpwww_server_header,
                    "ep_httpwww_server_version": data.ep_httpwww_server_version,
                },
            )
            print("made it past insert")
            if created:
                LOGGER.info("new PSHTT record created for %s", data.sub_domain)

            return {"message": "Record updated successfully.", "updated_data": data}

        except Exception as e:
            print(e)
            print("failed to insert or update")
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_darkweb_cves_breaches(), Issue 630 ---
@api_router.post(
    "/darkweb_cves",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.DarkWebCvesTaskResp,
    tags=["Get all darkweb cve data"],
)
def darkweb_cves(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all darkweb cve data"""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        task = darkweb_cves_task.delay()
        # Return the new task id w/ "Processing" status
        return {"task_id": task.id, "status": "Processing"}
    else:
        return {"message": "No api key was submitted"}


# --
@api_router.get(
    "/darkweb_cves/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    # \response_model=schemas.DarkWebCvesTaskResp,
    tags=["Check task status for darkweb_cves endpoint task."],
)
async def darkweb_cves_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """API endpoint to check status of darkweb_cves endpoint task."""
    # Retrieve task status
    task = darkweb_cves_task.AsyncResult(task_id)
    # Return appropriate message for status
    if task.state == "SUCCESS":
        return {"task_id": task_id, "status": "Completed", "result": task.result}
    elif task.state == "PENDING":
        return {"task_id": task_id, "status": "Pending"}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "status": "Failed", "error": str(task.result)}
    else:
        return {"task_id": task_id, "status": task.state}


# --- Issue 629 ---
# Query the darkweb data, It eithere hits the Alerts table or the Mentions Table
@api_router.post(
    "/darkweb_data",
    # response_model=schemas.DarkWebCvesTaskResp,
    tags=["Get darkweb data from either mentions or alerts table"],
)
def darkweb_data(data: schemas.DarkWebDataInput, tokens: dict = Depends(get_api_key)):
    """API Endpoint to query the darkweb data from either alerts table or mentions table."""
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            date_format = "%Y-%m-%d"
            try:
                sdate = datetime.datetime.strptime(data.start_date, date_format)
                edate = datetime.datetime.strptime(data.end_date, date_format)
            except ValueError:
                return {"message": "date is in wrong format"}
            print("testing")
            match data.table:
                case "mentions":
                    print("here")
                    mentions = list(
                        Mentions.objects.filter(
                            organizations_uid=data.org_uid, date__range=(sdate, edate)
                        ).values()
                    )
                    return mentions
                case "alerts":
                    alerts = mentions = list(
                        Alerts.objects.filter(
                            organizations_uid=data.org_uid, date__range=(sdate, edate)
                        ).values()
                    )
                    return alerts
        except:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Issue 627 ---
# Query domain masquerading alerts tables
@api_router.post(
    "/dom_masq_alerts",
    # response_model=schemas.DarkWebCvesTaskResp,
    tags=["query the domain masq alert data."],
)
def dom_masq_alerts(data: schemas.AlertInput, tokens: dict = Depends(get_api_key)):
    """API Endpoint to query the domain masq data."""
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            date_format = "%Y-%m-%d"
            try:
                sdate = datetime.datetime.strptime(data.start_date, date_format)
                edate = datetime.datetime.strptime(data.end_date, date_format)
            except:
                return {"message": "date is in wrong format"}
            mentions = list(
                DomainAlerts.objects.filter(
                    organizations_uid=data.org_uid, date__range=(sdate, edate)
                ).values()
            )
            return mentions
        except:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Issue 626 ---
# Query domain masquerading on the domain permutattions tables
@api_router.post(
    "/dom_masq",
    # response_model=schemas.DarkWebCvesTaskResp,
    tags=["query the domain masq data."],
)
def dom_masq(data: schemas.AlertInput, tokens: dict = Depends(get_api_key)):
    """API Endpoint to query the domain masq data."""
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            date_format = "%Y-%m-%d"
            try:
                sdate = datetime.datetime.strptime(data.start_date, date_format)
                edate = datetime.datetime.strptime(data.end_date, date_format)
            except:
                return {"message": "date is in wrong format"}
            mentions = list(
                DomainPermutations.objects.filter(
                    organizations_uid=data.org_uid, date_active__range=(sdate, edate)
                ).values()
            )
            return mentions
        except:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}
