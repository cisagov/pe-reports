import os

from pe_reports.data.configOriginal import config1
import psycopg2
import psycopg2.extras
from flask_sqlalchemy import SQLAlchemy
from pe_reports import app
from sqlalchemy import create_engine

# basedir = os.path.abspath(os.path.dirname(__file__))

params = config1()

# conn = psycopg2.connect(**params)
DATABASE_URL = f'postgresql+psycopg2://{params["user"]}:{params["password"]}@{params["host"]}:{params["port"]}/{params["database"]}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
db = SQLAlchemy(app)
engine = create_engine(DATABASE_URL)
try:

    result = engine.execute('select * from organizations')

    for x in result:
        print(x)

except:
    print('Something is wrong')



# class Config(object):
#     DATABASE_URL = DB_URL = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'
#     SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
#     DEBUG = True
#     CSRF_ENABLED = True


