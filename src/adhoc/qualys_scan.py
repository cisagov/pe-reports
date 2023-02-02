
import requests
import json 
import csv
from datetime import datetime
from retry import retry
import logging

now = datetime.now().strftime("%Y-%m-%d")


LOGGER = logging.getLogger(__name__)

url = "https://qualysapi.qg3.apps.qualys.com/"
username = ""
password = ""

from data.run import insertWASIds, insertFindingData, insertCountData

class InvalidQualysCall(Exception):
    """Raise When qualys returns an error."""

class InvalidApiCall(Exception):
    """Raise when the API call is invalid or no data is returned."""


@retry((InvalidApiCall,InvalidQualysCall), tries=3, delay=2, backoff=2)
def qualys_call(link,header,data):
    """Make a call to Qualys API."""
    response = requests.post(link, headers=header,data=json.dumps(data))
    if response.status_code != 200:
        LOGGER.error("Error Code: %s", response.status_code)
        raise InvalidQualysCall
    responseJson = json.loads(response.text)
    if responseJson['ServiceResponse']['responseCode'] != 'SUCCESS':
        LOGGER.error(responseJson['ServiceResponse']['responseCode'])
        raise InvalidApiCall
    return responseJson


def iterateCustomers():
    """Iterate through all customers from the stakeholders csv file."""
    customerID = []
    with open('cyhy_stakeholders_list.csv', 'r') as csvfile:
        datareader = csv.reader(csvfile)
        for row in datareader:
            if row[4] != '':
                customerID.append(row[4])
    return customerID

def getWebAppFromTag(tagStr):
    """Get all webapps from a given tag."""
    endPoint = "qps/rest/3.0/search/was/webapp"
    headers = {
        'Content-Type' : "application/json",
        'accept' : "application/json",
        'user' : username,
        'password' : password
        }
    data = {
        "ServiceRequest": {
            "filters": {
                "Criteria":  [
                    {
                    "field" : "tags.name",
                    "operator" : "EQUALS",
                    "value" : tagStr
                    }
                ]
            }
        }
    }
    we = qualys_call(url+endPoint,headers,data)
    domainList = []
    for x in we['ServiceResponse']['data']:
        name = x['WebApp']['name']
        ids = x['WebApp']['id']
        domainList.append({'name':name,'id':ids})
    return domainList

def getFindingsFromId(idStr):
    """Get all findings from a given ID."""
    endPoint = "qps/rest/3.0/search/was/finding"
    headers = {
        'Content-Type' : "application/json",
        'accept' : "application/json",
        'user' : username,
        'password' : password
        }
    data = {
        "ServiceRequest": {
            "preferences": 
                {
                    "verbose": "true"
                },
            "filters": {
                "Criteria":  [
                    {
                        "field" : "webApp.tags.name",
                        "operator" : "EQUALS",
                        "value" : idStr
                    },
                    {
                        "field" : "type",
                        "operator" : "EQUALS",
                        "value" : "VULNERABILITY"
                    },
                    {
                        "field" : "status",
                        "operator" : "EQUALS",
                        "value" : "ACTIVE"
                    }
                ]
            }
        }
    }
    we = qualys_call(url+endPoint,headers,data)

    findings = we['ServiceResponse']['data']
    findingsList = []
    for x in findings:
        findingType = x['Finding']['type']
        uid = x['Finding']['uniqueId']
        severity = x['Finding']['severity']
        name = x['Finding']['name']
        cvssV3 = x['Finding']['cvssV3']
        owasp_category = x['Finding']['owasp']['list'][0]['OWASP']['name']
        timesDetected = x['Finding']['timesDetected']
        firstDetected = x['Finding']['firstDetectedDate']
        lastDetected = x['Finding']['lastDetectedDate']
        findingsList.append({
                            'finding_uid':uid,
                            'finding_type':findingType,
                            'org_id':idStr,
                            'name':name,
                            'owasp_category':owasp_category,
                            'type':findingType,
                            'severity':severity,
                            'times_detected':timesDetected,
                            'base_score':cvssV3['base'],
                            'temporal_score':cvssV3['temporal'],
                            'status':'ACTIVE',
                            'last_detected':lastDetected,
                            'first_detected':firstDetected,
                            'date':now
                            })
    return findingsList

def getActiveVulnCount(idStr):
    endPoint = "qps/rest/3.0/count/was/finding"
    headers = {
        'Content-Type' : "application/json",
        'accept' : "application/json",
        'user' : username,
        'password' : password
        }
    data = {
        "ServiceRequest": {
            "filters": {
                "Criteria":  [
                    {
                        "field" : "webApp.tags.name",
                        "operator" : "EQUALS",
                        "value" : idStr
                    },
                    {
                        "field" : "type",
                        "operator" : "EQUALS",
                        "value" : "VULNERABILITY"
                    },
                    {
                        "field" : "status",
                        "operator" : "EQUALS",
                        "value" : "ACTIVE"
                    }
                ]
            }
        }
    }
    we = qualys_call(url+endPoint,headers,data)
    return we['ServiceResponse']['count']

def getWebAppCount(idStr):
    endpoint = "qps/rest/3.0/count/was/webapp"
    headers = {
        'Content-Type' : "application/json",
        'accept' : "application/json",
        'user' : username,
        'password' : password
        }
    data = {
        "ServiceRequest": {
            "filters": {
                "Criteria":  [
                    {
                        "field" : "tags.name",
                        "operator" : "EQUALS",
                        "value" : idStr
                    }
                ]
            }
        }
    }
    we = qualys_call(url+endpoint,headers,data)
    return we['ServiceResponse']['count']


def main():
    customers = iterateCustomers()[1:]
    wasFindings = []
    if username == "":
        username = input("Enter Username: ")
        password = input("Enter Password: ")
    
    for x in customers:
        wasFrame = {
            'org_id': x,
            'webapp_count' : getWebAppCount(x),
            'webapp_active_vuln_count' : getActiveVulnCount(x),
            'date' : now
        }
        wasFindings.append(wasFrame)
        print(wasFrame)
        insertCountData([wasFrame])
        LOGGER.info("Successfully Found Data for " + x)
    
    for x in customers:
        findingList = getFindingsFromId(x)
        insertFindingData(findingList)
        LOGGER.info("Successfully Inserted Data for " + x)

if __name__ == "__main__":
    main()