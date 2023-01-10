from typing import List, Any, Union
from datetime import datetime, timedelta
import json
import requests
import logging
import re
import asyncio

from fastapi import \
    APIRouter,\
    FastAPI,\
    Body,\
    Depends,\
    HTTPException,\
    status,\
    Security
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.api_key import \
    APIKeyQuery,\
    APIKeyCookie,\
    APIKeyHeader,\
    APIKey
# from . import schemas
# from .models import apiUser
# from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages


from starlette.status import HTTP_403_FORBIDDEN
from jose import jwt, exceptions
from asgiref.sync import sync_to_async
from decouple import config

from home.models import Organizations

from .models import apiUser
from . import schemas

LOGGER = logging.getLogger(__name__)




oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

api_router = APIRouter()


ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
ALGORITHM = "HS256"
JWT_SECRET_KEY = config('JWT_SECRET_KEY')   # should be kept secret
JWT_REFRESH_SECRET_KEY = config('JWT_REFRESH_SECRET_KEY')   # should be kept secret

API_KEY_NAME = "access_token"
COOKIE_DOMAIN = "localtest.me"

# TODO following api_key_query was left intentionally for future development
#   to pass query to api call see issue#
# api_key_query = APIKeyQuery(name=API_KEY_NAME, auto_error=False)
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)



def create_access_token(subject: Union[str, Any],
                        expires_delta: int = None) -> str:
    """Create access token"""
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt


def create_refresh_token(subject: Union[str, Any],
                         expires_delta: int = None) -> str:
    """Create a refresh token"""
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(
            minutes=REFRESH_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt

def userinfo(theuser):
    """Get all users in a list."""
    user_record = list(User.objects.filter(username=f'{theuser}'))

    if user_record:
        for u in user_record:
            return u.id


def userapiTokenUpdate(expiredaccessToken, user_refresh, theapiKey, user_id):
    """When api apiKey is expired a new key is created
       and updated in the database."""
    theusername = ''
    user_record = list(User.objects.filter(id=f'{user_id}'))
    # user_record = User.objects.get(id=user_id)


    for u in user_record:
        theusername = u.username
        theuserid = u.id
    LOGGER.info(f'The username is {theusername} with a user of {theuserid}')

    updateapiuseraccessToken = apiUser.objects.get(apiKey=expiredaccessToken)
    # updateapiuserrefreshToken = apiUser.objects.get(refresh_token=expiredrefreshToken)

    updateapiuseraccessToken.apiKey = f"{create_access_token(theusername)}"
    # updateapiuserrefreshToken.refresh_token = f"{create_refresh_token(theusername)}"
    # LOGGER.info(updateapiuseraccessToken.apiKey)

    updateapiuseraccessToken.save(update_fields=['apiKey'])
    # updateapiuserrefreshToken.save(update_fields=['refresh_token'])
    LOGGER.info(f'The user api key and refresh token have been updated from: {theapiKey} to: {updateapiuseraccessToken.apiKey}.')



def userapiTokenverify(theapiKey):
    """Check to see if api key is expired."""
    tokenRecords = list(apiUser.objects.filter(apiKey=theapiKey))
    user_key = ''
    user_refresh = ''
    user_id = ''

    for u in tokenRecords:
        user_refresh = u.refresh_token
        user_key = u.apiKey
        user_id = u.id
    # LOGGER.info(f'The user key is {user_key}')
    # LOGGER.info(f'The user refresh key is {user_refresh}')
    LOGGER.info(f'the token being verified at verify {theapiKey}')

    try:
        jwt.decode(theapiKey, config('JWT_REFRESH_SECRET_KEY'),
                   algorithms=ALGORITHM,
                   options={"verify_signature": False})
        LOGGER.info(f'The api key was alright {theapiKey}')

    except exceptions.JWTError as e:
        LOGGER.warning('The access token has expired and will be updated')
        userapiTokenUpdate(user_key, user_refresh, theapiKey, user_id)


async def get_api_key(
    # api_key_query: str = Security(api_key_query),
    api_key_header: str = Security(api_key_header),
    # api_key_cookie: str = Security(api_key_cookie),
):
    """Get api key from header."""

    if api_key_header != '':
        return api_key_header

    else:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials"
        )


# def api_key_auth(api_key: str = Depends(oauth2_scheme)):
#     if api_key not in api_keys:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Forbidden"
#         )





@api_router.post("/orgs", dependencies=[Depends(get_api_key)],
                response_model=List[schemas.Organization], tags=["List of all Organizations"])
def read_orgs(tokens: dict = Depends(get_api_key)):
    """API endpoint to get all stakeholders."""
    orgs = list(Organizations.objects.all())

    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return orgs
    except:
        LOGGER.info('API key expired please try again')


# @api_router.post("/dnsMasq", dependencies=[Depends(get_api_key)],
#                 response_model=List[schemas.Organization], tags=["List domain masquerading"])
# def read_orgs(tokens: dict = Depends(get_api_key)):
#     """API endpoint to get all stakeholders."""
#     masq = list(DnstwistDomainMasq.objects.all())
#
#     LOGGER.info(f"The api key submitted {tokens}")
#     try:
#         userapiTokenverify(theapiKey=tokens)
#         return masq
#     except:
#         LOGGER.info('API key expired please try again')


@api_router.post("/get_key", tags=["Get user api keys"])
def read_orgs(data: schemas.UserAPI):
    """API endpoint to get api by submitting refresh token."""
    user_key = ''
    userkey = list(apiUser.objects.filter(refresh_token=data.refresh_token))
    LOGGER.info(f'The input data requested was ***********{data.refresh_token[-10:]}')

    for u in userkey:
        user_key = u.apiKey
    return user_key

















@api_router.post("/testingUsers",
                tags=["List of user id"])
def read_users(data: schemas.UserAuth):
    user = userinfo(data.username)

    # user = list(User.objects.filter(username='cduhn75'))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this name does exist"
        )
    return userinfo(data.username)



# @api_router.get("/secure_endpoint", tags=["test"])
# async def get_open_api_endpoint(api_key: APIKey = Depends(get_api_key)):
#     print(api_key)
#     response = "How cool is this?"
#     return response


@api_router.post('/signup', summary='Create api key and access token on user', tags=['Sign-up to add api_key and access token to user'])
def create_user(data: schemas.UserAuth):
    # querying database to check if user already exist
    user = userinfo(data.username)

    #TODO put logging statement here.
    print(f'The user id is {user}\n')
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this username does not exist"
        )

    theNewUser = apiUser(
        apiKey=create_access_token(data.username),
        user_id=user,
        refresh_token=create_refresh_token(data.username)
    )
    apiUser.save(theNewUser)
    return theNewUser



# @api_router.get("/items/")
# async def read_items(token: str=Depends(oauth2_scheme)):
#     return {"token": token}


