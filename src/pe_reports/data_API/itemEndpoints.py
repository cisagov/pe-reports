"""The router file creates API endpoints."""

# from pe_reports.data_API.apiutils import userinfo
from pe_reports.data_API.apiutils import userinfo
# from pe_reports.data_API.models import UserAPI

# Third-Party Libraries
from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import uuid

from pe_reports.data_API.schema import UserOut, UserAuth, TokenSchema

from pe_reports.data_API.apiutils import \
    get_hashed_password,\
    create_access_token,\
    create_refresh_token,\
    verify_password


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

router = APIRouter()


@router.get("/v1", tags=["items"])
async def read_items(token: str = Depends(oauth2_scheme)):
    """Retrieve usernames that will be shared."""
    return {"token": token}
    # return [{"username": "Craig"}, {"username": "Mike"}]


@router.get("/v1/people", tags=["people"])
async def read_items2():
    """Retrieve usernames that will be shared."""
    # return {"token": token}
    return [{"username": "Craig"}, {"username": "Mike"}]


@router.post('/v1/loginAPI', summary="Create access and refresh tokens for user",
             response_model=TokenSchema)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = UserAPI.get(form_data.username, None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )

    hashed_pass = user['password']
    if not verify_password(form_data.password, hashed_pass):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )

    return {
        "access_token": create_access_token(user['email']),
        "refresh_token": create_refresh_token(user['email']),
    }


@router.post('/v1/signupAPI', summary="Create new user", response_model=UserOut)
async def create_user(data: UserAuth):
    # querying database to check if user already exist
    user = userinfo(data.email)
    print(user)
    if user is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exist"
        )
    user = {
        'email': data.email,
        'password': get_hashed_password(data.password),
        'id': str(uuid.uuid4())
    }
    db[data.email] = user  # saving user to database
    return user
