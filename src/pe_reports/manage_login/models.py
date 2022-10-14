from pe_reports import db, login_manager

#Third party packages
from sqlalchemy.dialects.postgresql import UUID
import uuid
from flask_bcrypt import Bcrypt
from flask_login import UserMixin



bcrypt = Bcrypt()


@login_manager.user_loader
def load_user(user_id):

    return User.query.get(user_id)


class User(db.Model, UserMixin):
    """Create User table in db. Both the system users and API users will be here
    the API users will have an api_key present in the api_key field.
    """

    __tablename__ = 'Users'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(64), unique=True, index = True)
    username = db.Column(db.String(64), unique=True, index=True)
    admin = db.Column(db.Integer)
    role = db.Column(db.Integer)
    password_hash = db.Column(db.String(128))
    api_key = db.Column(db.String(128), unique=True)
    refrest_token = db.Column(db.String(128), unique=True)

    def __init__(self, email, username, password):

        self.email = email
        self.username = username
        self.admin = 0
        self.role = 0
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class UserAPI(db.Model, UserMixin):
    """Create User table in db. Both the system users and API users will be here
    the API users will have an api_key present in the api_key field.
    """

    __tablename__ = 'UsersAPI'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(64), unique=True, index = True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    api_key = db.Column(db.String(128), unique=True)
    refrest_token = db.Column(db.String(128), unique=True)

    def __init__(self, email, username, password):

        self.email = email
        self.username = username
        self.api_key = 0
        self.refrest_token = 0
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
