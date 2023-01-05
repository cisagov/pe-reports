from jose import jwt, exceptions
import requests
import pprint

from decouple import config
import json
from typing import List, Any, Union
from datetime import datetime, timedelta
from jose.jwt import ExpiredSignatureError

ACCESS_TOKEN_EXPIRE_MINUTES = 1  # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 1  # 7 days
ALGORITHM = "HS256"
JWT_SECRET_KEY = config('JWT_SECRET_KEY')   # should be kept secret
JWT_REFRESH_SECRET_KEY = config('JWT_REFRESH_SECRET_KEY')   # should be kept secret
#
url = "https://api.github.com/issues"
urlOrgs = 'http://127.0.0.1:8000/apiv1/orgs'
urlIDs = 'http://127.0.0.1:8000/apiv1/get_key'
urlAllOpenIssues1 = "https://api.github.com/repos/cisagov/pe-reports/issues?per_page=100&state=open&page=1"
urlAllOpenIssues2 = "https://api.github.com/repos/cisagov/pe-reports/issues?per_page=100&state=open&page=2"
urlAllAssignee = "https://api.github.com/repos/cisagov/pe-reports/assignees"

listURL = [urlAllOpenIssues1, urlAllOpenIssues2]


# The client should pass the API key in the headers
headers = {
    'Content-Type': 'application/json',
    'access_token': f'{config("API_KEY")}'
}

headersID = {
    'Content-Type': 'application/json',
    'user_id': f'{config("USER_REFRESH_TOKEN")}',
}


def create_access_token(subject: Union[str, Any],
                        expires_delta: int = None) -> str:
    if expires_delta is not None:

        expires_delta = datetime.utcnow() + expires_delta
    else:

        expires_delta = datetime.utcnow() + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt



def getallpages():
    response = ''
    pages = []
    # print(headers['access_token'])
    # print(config('API_KEY'))
    try:

        response = requests.get(urlOrgs, headers=headers).json()
        return response

    except requests.exceptions.HTTPError as errh:
        print('its 1')
        print(errh)
    except requests.exceptions.ConnectionError as errc:
        print('its 2')
        print(errc)
    except requests.exceptions.Timeout as errt:
        print('its 3')
        print(errt)
    except requests.exceptions.RequestException as err:
        print('its 4')
        print(err)
    except json.decoder.JSONDecodeError as err:
        print('its 5')
        print(err)
        # pp = pprint.PrettyPrinter(indent=4)
        # pp.pprint(response)  # => "You used a valid API key."

        # for x in response:
            # print(x.keys())
            # pages.append(x['number'])
            # print(x['number'])
            # print("/n")
            # print(x['body'])
    # return print(response)



def getUserKey():
    payload = json.dumps({
        "refresh_token": f'{config("USER_REFRESH_TOKEN")}'
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", urlIDs, headers=headers, data=payload).json()

    return response




# def getGHUsers(url):
#     users = []
#     response = requests.get(url, headers=headers).json()
#     # pp = pprint.PrettyPrinter(indent=4)
#     # pp.pprint(response)  # => "You used a valid API key."
#
#     for x in response:
#         # print(x.keys())
#         users.append(x['login'])
#
#     return users



# newToken = create_access_token('cduhn75')

# print(f'The new token is {newToken}')





def checkAcessExpiration():
    # user_access = create_access_token('cduhn75')
    user_access =  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzIxNjkwNjgsInN1YiI6ImNkdWhuNzUifQ.Y5FyjT8216mIHYw3sqvnuoAxVcYNhZQ3i6u1aZCJL78'
    print(user_access)
    # print(config('JWT_REFRESH_SECRET_KEY'))

    try:
        # header_data = jwt.get_unverified_header(user_access)

        mine = jwt.decode(user_access, config('JWT_REFRESH_SECRET_KEY'),
                          algorithms=ALGORITHM,
                          options={"verify_signature": False})
        print(mine)


    except exceptions.JWTError as e:
        print(f'The token is expired {e}')


# checkAcessExpiration()
print(getallpages())
#
# print(getUserKey())
# print(getallpages()[1])


# print(config('API_KEY'))
# for page in getallpages():
#     print(page)

# print(getGHUsers(urlAllAssignee))

# from django.contrib.auth.models import User
#
# from home.models import Organizations
#
#
#
#
# def userinfo(theuser):
#     user_record = User.objects.filter(username=theuser)
#     if user_record:
#         return user_record.id
#
#
# def read_orgs():
#     orgs = list(Organizations.objects.all())
#
#     return orgs
#
#
# print(read_orgs())