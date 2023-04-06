
import requests
import json 
import csv
from datetime import datetime
from retry import retry
import logging
import pandas as pd
from requests.auth import HTTPBasicAuth

now = datetime.now().strftime("%Y-%m-%d")


LOGGER = logging.getLogger(__name__)

url = "https://qualysapi.qg3.apps.qualys.com/"
username = ""
password = ""

from data.run import insertWASIds, insertFindingData, insertCountData,queryVulnWebAppCount,queryWASOrgList

exampleData = [{
    'finding_uid':'803ecd02-71ee-456f-b8d0-3ee5f4022fb7',
    'finding_type':'VULNERABILITY',
    'webapp_id':'123456',
    'was_org_id':'TEST',
    'owasp_category':'A1:2017-Injection',
    'severity':4,
    'times_detected':6,
    'base_score':5.4,
    'temporal_score':5.4,
    'fstatus':'ACTIVE',
    'last_detected':'2023-01-26',
    'first_detected':'2022-06-26',
}]

exampleWasCustomer = [{
    'was_org_id':'TEST',
    'webapp_count':2,
    'active_vuln_count':69,
    'webapp_with_vuln_count':2,
    'last_updated':'2021-01-26',
}]

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

def getFindingsFromId(idStr,block=0):
    """Get all findings from a given ID."""
    if block == 0:
        offset = 1
    else:
        offset = block*1000
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
                    "limitResults": 1000,
                    "startFromOffset": offset,
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
                    }
                ]
            }
        }
    }
    we = qualys_call(url+endPoint,headers,data)
    
    try: 
        findings = we['ServiceResponse']['data']
    except KeyError:
        LOGGER.info("No Findings Found for: " + idStr)
        return []
    findingsList = []
    for x in findings:
        webapp_id = int(x['Finding']['webApp']['id'])
        findingType = x['Finding']['type']
        uid = x['Finding']['uniqueId']
        severity = x['Finding']['severity']
        name = x['Finding']['name']
        try:   
            cvssV3 = x['Finding']['cvssV3']
            base = cvssV3['base']
            temporal = cvssV3['temporal']
        except:
            base = 0
            temporal = 0
        try:
            owasp_category = x['Finding']['owasp']['list'][0]['OWASP']['name']
        except:
            owasp_category = 'None'
        status = x['Finding']['status']
        timesDetected = x['Finding']['timesDetected']
        firstDetected = x['Finding']['firstDetectedDate']
        lastDetected = x['Finding']['lastDetectedDate']
        findingsList.append({
                            'finding_uid':uid,
                            'finding_type':findingType,
                            'webapp_id':webapp_id,
                            'was_org_id':idStr,
                            'name':name,
                            'owasp_category':owasp_category,
                            'severity':severity,
                            'times_detected':timesDetected,
                            'base_score':base,
                            'temporal_score':temporal,
                            'fstatus':status,
                            'last_detected':lastDetected,
                            'first_detected':firstDetected,
                            'date':now
                            })
    if we['ServiceResponse']['hasMoreRecords'] == 'true':
        findingsList.extend(getFindingsFromId(idStr,block+1))
    return findingsList

def getActiveVulnCount(idStr,status):
    """Get the number of active vulnerabilities from a given ID."""
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
                        "value" : status
                    }
                ]
            }
        }
    }
    we = qualys_call(url+endPoint,headers,data)
    return we['ServiceResponse']['count']

def getWebAppCount(idStr):
    """Get the number of webapps from a given ID."""
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

def remidiationTime(firstDetected,lastDetected):
    """Calculate the time between first detected and last detected."""
    firstDetected = datetime.strptime(firstDetected, "%Y-%m-%dT%H:%M:%S")
    lastDetected = datetime.strptime(lastDetected, "%Y-%m-%dT%H:%M:%S")
    time = lastDetected - firstDetected
    return time.days


def getAllRemidiationTime(findingList):
    crit = []
    high = []
    for finding in findingList:
        if finding['severity'] == 4:
            high.append(remidiationTime(finding['first_detected'][0:19],finding['last_detected'][0:19]))
        if finding['severity'] == 5:
            crit.append(remidiationTime(finding['first_detected'][0:19],finding['last_detected'][0:19]))
        
    return sum(crit)/len(crit),sum(high)/len(high)

def print_this(ok):
    with open("vuln.csv",'a',newline='') as file:
        writer = csv.writer(file)
        writer.writerow(list(ok[0]))
        for x in ok:
            keys = list(x)
            values = []
            for key in keys:
                values.append(x[key])
            writer.writerow(values)

def main():
    customers = iterateCustomers()[1:]
    insertWASIds(customers)
    query = queryWASOrgList()
    for was_org_id in query:
        findingList = getFindingsFromId(was_org_id)
        if findingList != []:
            insertFindingData(findingList)
        
    for x in query:
        wasFrame = {
            'was_org_id': x,
            'webapp_count' : getWebAppCount(x),
            'active_vuln_count' : getActiveVulnCount(x,'ACTIVE') + getActiveVulnCount(x,'REOPENED') + getActiveVulnCount(x,'NEW'),
            'webapp_with_vulns_count' :queryVulnWebAppCount(x),
            'last_updated' : now
        }
        insertCountData(wasFrame)
        LOGGER.info("Successfully inserted Data for " + x)

if __name__ == "__main__":
    main()

