"""Produce a count of darkweb metions that correlate to stakeholder."""
# Standard Python Libraries
from datetime import datetime
import logging
import os.path
import re
import string
from time import sleep
import platform
import sys

# Third-Party Libraries
from googletrans import Translator
import httpcore
from langdetect import DetectorFactory, detect
import langdetect.lang_detect_exception
import nltk
from nltk.corpus import stopwords
import pandas as pd
import psycopg2
import psycopg2.extras
from psycopg2 import OperationalError
import requests
from sklearn.decomposition import LatentDirichletAllocation
from sklearn.feature_extraction.text import CountVectorizer
import sshtunnel
from sshtunnel import SSHTunnelForwarder

# cisagov Libraries
from pe_reports.data.config import config

logging.basicConfig(format="%(asctime)-15s %(levelname)s %(message)s",
                    level=logging.INFO)

CONN_PARAMS_DIC = config()

# CSG credentials
API_Client_ID = os.getenv("CSGUSER")
API_Client_secret = os.environ.get("CSGSECRET")

today = datetime.today().strftime('%Y-%m-%d')
the_file = "/Users/duhnc/Desktop/craigout.csv"
the_platform = platform.system()

##The next line may be deleted

DetectorFactory.seed = 0

sshConnected = os.popen('w').read()


def show_psycopg2_exception(err):
    """Handle errors for PostgreSQL issues."""
    err_type, err_obj, traceback = sys.exc_info()
    logging.error(
        "Database connection error: %s on line number: %s", err,
        traceback.tb_lineno
    )


def getToken():
    """Will get authorization token from CSG."""
    d = {
        "grant_type": "client_credentials",
        "client_id": f"{API_Client_ID}",
        "client_secret": f"{API_Client_secret}",
    }
    r = requests.post("https://api.cybersixgill.com/auth/token", data=d)
    r = r.text.split(":")
    r = r[1].lstrip('"').rsplit('"')[0]
    return r


def thesshTunnel():
    """SSH Tunnel to the Crossfeed database instance."""
    os.system('checkAccessor.py')
    sleep(3)
    server = SSHTunnelForwarder(
        ('localhost'),
        ssh_username="ubuntu",
        ssh_pkey="~/Users/$USER/.ssh/accessor_rsa",
        remote_bind_address=(
            'crossfeed-stage-db.c4a9ojyrk2io.us-east-1.rds.amazonaws.com',
            5432)
    )
    server.start()

    return server.local_bind_port


def connect():
    """Connect to PostgreSQL database."""
    conn = None

    if platform.system() != 'Darwin':
        try:
            logging.info("Connecting to the PostgreSQL......")
            conn = psycopg2.connect(**CONN_PARAMS_DIC)
            logging.info("Connection successful......")
        except OperationalError as err:
            show_psycopg2_exception(err)
            conn = None
        return conn
    else:
        theport = thesshTunnel()
        try:

            logging.info("****SSH Tunnel Established****")

            conn = psycopg2.connect(
                host='127.0.0.1', user=os.getenv('PE_DB_USER'),
                password=os.getenv('PE_DB_PASSWORD'),
                dbname=os.getenv('PE_DB_NAME'),
                port=theport
            )

            return conn
        except OperationalError as err:
            show_psycopg2_exception(err)
            conn = None

            return conn


def get_orgs(conn):
    """Query organizations table."""
    try:
        cur = conn.cursor()
        sql = """SELECT * FROM organizations"""
        cur.execute(sql)
        pe_orgs = cur.fetchall()
        cur.close()
        return pe_orgs
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            conn.close()


def getorgsInfo(org_name):
    """Get all organizaiton names from P&E database."""
    # global conn, cursor
    conn = connect()
    cursor = ''
    resultList = []
    resultDict = {}
    logging.info(org_name)


    try:
        # Print all the databases
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        query = "select organizations_uid, cyhy_db_name " \
                "from organizations where cyhy_db_name like '%s'" % (
                            '%' + org_name)
        cursor.execute(query)
        result = cursor.fetchall()

        for row in result:
            # print(row)
            theorg = row[0]
            thename = row[1]
            resultDict[theorg] = thename

        return resultDict
    except sshtunnel.BaseSSHTunnelForwarderError:
        logging.info(
            'The ssh screen has not been started,'
            ' and will start momentairly.')
    finally:
        conn.close()


def getorgTopicCount(today):
    """Get all organizaiton names from P&E database."""
    # global conn, cursor
    conn = connect()
    cursor = ''
    resultList = []
    resultDict = {}


    try:
        # Print all the databases
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        query = "select organizations_uid, content_count " \
                "from topic_totals where count_date like '%s'" % ('%' + today)
        cursor.execute(query)
        result = cursor.fetchall()

        for row in result:
            # print(row)
            theorg = row[0]
            thecount = row[1]
            resultDict[theorg] = thecount

        return resultDict
    except sshtunnel.BaseSSHTunnelForwarderError:
        logging.info(
            'The ssh screen has not been started,'
            ' and will start momentairly.')
    finally:
        conn.close()





def setorgsCountInfo(org_id, org_name):
    """Set mention counts per organization and the date found."""
    # global conn, cursor
    conn = connect()
    cursor = ''
    resultList = []
    resultDict = {}
    logging.info(org_name)

    try:
        # Print all the databases
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        query = "insert into " \
                "topic_totals(organizations_uid, content_count) " \
                "values ('%s','%s')" % (org_id, org_name)
        cursor.execute(query)


        return resultDict
    except sshtunnel.BaseSSHTunnelForwarderError:
        logging.info(
            'The ssh screen has not been started,'
            ' and will start momentairly.')
    finally:
        if conn is not None:
            conn.commit()
            cursor.close()
            conn.close()
            # os.popen('pkill -1 ssh')
            logging.info('The connection/query was completed and closed.')


def sshgetcsv(startdate, report_period):
    '''This function ssh tunnels to the PE Reports database
    and queries the mentions table for the report period.'''

    # This is the raw data from CSG, to be passed to thetopics.py
    saveCSV = f'{startdate}_{report_period}_reportperiod.csv'

    if not os.path.exists(saveCSV):
        conn = connect()

        try:
            # Print all the databases
            cursor = conn.cursor()
            query = "select to_date(split_part(collection_date,'T',1),'YYYY MM DD')," \
                    " content," \
                    " sixgill_mention_id," \
                    "post_id," \
                    " organizations_uid" \
                    " from mentions " \
                    "where to_date(split_part(collection_date,'T',1),'YYYY MM DD') >" \
                    " to_date('%s', 'YYYY MM DD') -  interval '%s DAY'" % (
                    startdate, report_period)
            results = "COPY (%s) TO STDOUT WITH CSV HEADER " % query

            with open(saveCSV, 'w') as file:
                cursor.copy_expert(results, file)
        except sshtunnel.BaseSSHTunnelForwarderError:
            logging.info(
                'The ssh screen has not been started, and will start momentairly.')



        finally:
            logging.info('Made it to finally ')
            conn.close()
            thetopics(saveCSV)



    else:
        logging.info(
            'The mentions csv has already been created for this date and period.')
        thetopics(saveCSV)


# TODO: This function will be utilized in the future but needs some
#   improvements and implementation
# def getnames(thearticle):
#     """This functinon is Name Entity Recognition to extract executives names
#     from stakeholder website.
#     """
#
#     text1 = NER(thearticle)
#
#     for word in text1.ents:
#         print(word.text, word.label_)


def getStakeholderInfo():
    """Get list of stakeholders from CSG."""
    url = "https://api.cybersixgill.com/multi-tenant/organization"
    # url = "https://api.cybersixgill.com/intel/intel_items?query=credentials: dhs.gov"

    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache',
        'Authorization': f'Bearer {getToken()}',
        }

    response = requests.request("GET", url, headers=headers, data=payload)
    response = response.json()



    with open('theOrgs.txt', 'a') as file:
        for name in response:
            # print(name.keys())
            name = name['name']
            file.write(f'{name}\n')


def thetopics(saveCSV):
    '''This function creates a list that of topics that correlate stakeholders
    to the mentions that come from CSG.

    '''
    logging.info('The program is starting.')
    orgfile = 'theOrgs.txt'
    allOrgs = []
    the_new_file = 'newCSV.csv'
    if os.path.exists(orgfile):
        logging.info('The array is being populated')
        with open(orgfile, 'r') as orgfile:
            for org in orgfile:
                allOrgs.append(org.strip())
            orgfile.close()

    else:
        getStakeholderInfo()

    if os.path.exists(the_new_file):
        logging.info("Started making topics")
        DetectorFactory.seed = 0

        nan_value = float('NaN')

        nltk.download('stopwords')

        stops = set(stopwords.words('english'))

        stopwordsfile = open('additionalstopwords.txt', 'a+')
        newstopwordlist = []

        with open('additionalstopwords.txt', 'r+') as wordfile:
            allstopwords = wordfile.read().splitlines()

        # To add stop words to the set of stopwords
        stops = stops.union({word for word in allstopwords if word not in stops
                             })



        df = pd.read_csv(the_new_file,
                         engine='python',
                         on_bad_lines='skip')


        df.replace("", nan_value, inplace=True)
        df['content'] = df['content'].str.rstrip(string.digits)
        #
        df.dropna(subset=['content'], inplace=True)
        allContent = df['content']


        cv = CountVectorizer(max_df=0.99, min_df=2, stop_words=stops)

        dtm = cv.fit_transform(df['content'])


        # The following sets the total number of topics to be returned
        LDA = LatentDirichletAllocation(n_components=10, random_state=42)

        LDA.fit(dtm)

        with open('./theOrgs.txt') as f:
            organization = f.read().splitlines()

        for i, topic in enumerate(LDA.components_):

            thetopicList = [cv.get_feature_names_out()[index] for index in
                            topic.argsort()[-15:]]

            for atopic in thetopicList:
                if atopic.isnumeric():
                    newstopwordlist.append(atopic)

                else:
                    pass

                if newstopwordlist:
                    for word in newstopwordlist:
                        if word not in allstopwords:
                            stopwordsfile.write(f'{word}\n')


                    thetopics(saveCSV)
                else:
                    pass

            for org in organization:
                if org != '':

                    org1 = org.split('_')
                    if len(org1) > 1:
                        org = org1[1].lower()
                    else:
                        org = org.lower()
                    if org in thetopicList:
                        print(f"The top 15 words for topic {i}")
                        print(f'{thetopicList}\n')
                        print(f'The org {org} FOUND \n')
                        topic_results = LDA.transform(dtm)

                        df['topic'] = topic_results.argmax(axis=1)

                        values = [i]
                        totalArticles = \
                        df[['content', 'topic']][df.topic.isin(values)].count()[
                            0]
                        theorgUUID = getorgsInfo(org_name=org.upper())

                        theorgValue = list(theorgUUID.values())[0]

                        theorgUUID = list(theorgUUID.keys())[
                            list(theorgUUID.values()).index(theorgValue)]
                        setorgsCountInfo(theorgUUID, totalArticles)

                        print(f'The article count is {totalArticles}\n\n')

                        df[['content', 'topic']][df.topic.isin(values)].to_csv(
                            f'{today}_{org}.csv')

                    else:
                        pass
                else:
                    pass

        os.remove(the_new_file)
        currentFiles = os.listdir(os.getcwd())
        for file in currentFiles:
            if file.endswith('reportperiod.csv'):
                os.remove(file)

    else:
        logging.info("The file didnt exist.")
        translateArticles(saveCSV)
        thetopics(saveCSV)


def translateArticles(saveCSV):
    nan_value = float('NaN')
    df = pd.read_csv(saveCSV,
                     engine='python',
                     on_bad_lines='skip')

    df.replace("", nan_value, inplace=True)

    df.dropna(subset=['content'], inplace=True)

    thecontent = df['content']
    # print(thecontent)
    thecontent = [line for line in thecontent if str(line).strip()]

    translator = Translator()
    count = 0


    for x in thecontent:
        # if count <= 10:
        #     print(f'The count is {count}')
        if isinstance(x, str):
            if len(x) > 300:
                # print(x)
                try:
                    the_lang = detect(x)
                    if the_lang != 'en':
                        translation = translator.translate(x)
                        df['content'] = df['content'].replace(x,
                                                              translation.text)
                        logging.info(translation.text)


                    else:
                        logging.info('The entry was english')
                except langdetect.lang_detect_exception.LangDetectException as nolang:
                    pass


                except AttributeError:
                    pass
                    # print(x)
                except TypeError:
                    pass

                except httpcore.ReadTimeout:
                    pass

                except re.error as reerror:
                    pass


    df.to_csv('./newCSV.csv')

