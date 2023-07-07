import requests
import json 
import csv
from datetime import datetime
from retry import retry
import logging
import pandas as pd
from requests.auth import HTTPBasicAuth
import re

now = datetime.now().strftime("%Y-%m-%d")


LOGGER = logging.getLogger(__name__)

url = "https://qualysapi.qg3.apps.qualys.com/"
username = ""
password = ""

from data.run import insertWASIds,getPreviousFindingsHistorical, insertFindingData,queryVulnWebAppCount,queryWASOrgList,getPEuuid,getPreviousFindings,queryVulnCountAll,queryVulnCountSeverity,insertWASVulnData

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
                customerID.append((row[4],row[3]))
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

def initializeWasMap():
    """Initialize the was_map table with all the orgs and their PE uuids."""
    customers = iterateCustomers()[1:]
    insertList = []
    for org in customers:
        if org[1] != '':
            insertList.append((org[0],getPEuuid(org[1])))
        else:
            insertList.append((org[0],''))
    insertWASIds(insertList)
    
def fillFindings():
    """fill was_findings table for current month."""
    query = queryWASOrgList()
    for was_org_id in reversed(query):
        print('Getting Data for ' + was_org_id)
        findingList = getFindingsFromId(was_org_id)
        print('Got Data for ' + was_org_id)
        if findingList != []:
            insertFindingData(findingList)

def fillData(report_period):
    """fill was_history table for current month."""
    pattern = r'\d{2}-\d{2}-\d{4}'
    if re.match(pattern,report_period):
        rpd = datetime.strptime(report_period,'%m-%d-%Y')
    else:
        LOGGER.error('Invalid Date Format')
        return
    query = queryWASOrgList()
    for was_org_id in query:
        recentFindings = getPreviousFindingsHistorical(was_org_id,1) #gets the uid to all the findings that were fixed in the last month
        highRemTimeList = []
        critRemTimeList = []
        for finding in recentFindings:
            if finding[12] == 1:
                highRemTime = 0
                critRemTime = 0
                firstDetected = finding[11]
                lastDetected = finding[10]
                severity = finding[5]
                if severity == 4:
                    delta = lastDetected - firstDetected
                    highRemTimeList.append(delta.days)
                if severity == 5:
                    delta = lastDetected - firstDetected
                    critRemTimeList.append(delta.days)
        if len(highRemTimeList) == 0:
            highRemTime = 0
        else:
            highRemTime = sum(highRemTimeList)/len(highRemTimeList)
        if len(critRemTimeList) == 0:
            critRemTime = 0
        else:
            critRemTime = sum(critRemTimeList)/len(critRemTimeList)
        was_data = {
            'was_org_id' : was_org_id,
            'date_scanned' : now,
            'vuln_cnt':queryVulnCountAll(was_org_id),
            'vuln_webapp_cnt': queryVulnWebAppCount(was_org_id),
            'web_app_cnt': getWebAppCount(was_org_id),
            'high_rem_time' : highRemTime,
            'crit_rem_time' : critRemTime,
            'report_period': rpd,
            'high_vuln_cnt':queryVulnCountSeverity(was_org_id,4),
            'crit_vuln_cnt':queryVulnCountSeverity(was_org_id,5),
            'high_rem_cnt':len(highRemTimeList),
            'crit_rem_cnt':len(critRemTimeList)
        }
        insertWASVulnData(was_data)
    
def lastMonthData():
    """Fill was_history table for last months data."""
    query = queryWASOrgList()
    for was_org_id in query:
        recentFindings = getPreviousFindingsHistorical(was_org_id,2) #gets the uid to all the findings that were fixed in the last month
        highRemTimeList = []
        critRemTimeList = []
        vuln_cnt = 0
        vuln_webapp_set = {}
        for finding in recentFindings:  
            vuln_cnt += 1
            highRemTime = 0
            critRemTime = 0
            firstDetected = finding[11]
            lastDetected = finding[10]
            severity = finding[5]
            fstatus = finding[9]
            webapp_id = finding[0]
            vuln_webapp_set.add(finding[0])# add finding uid to set
            
            if severity == 4:
                delta = lastDetected - firstDetected
                highRemTimeList.append(delta.days)
            if severity == 5:
                delta = lastDetected - firstDetected
                critRemTimeList.append(delta.days)
        if len(highRemTimeList) == 0:
            highRemTime = 0
        else:
            highRemTime = sum(highRemTimeList)/len(highRemTimeList)
        if len(critRemTimeList) == 0:
            critRemTime = 0
        else:
            critRemTime = sum(critRemTimeList)/len(critRemTimeList)
        
        
        #get the first day of the previoud month
        first = now.replace(day=1)
        last_month = first - datetime.timedelta(days=1)
        firstPrevMonth = last_month.replace(day=1)
        
        was_data = {
            'was_org_id' : was_org_id,
            'date_scanned' : firstPrevMonth,
            'vuln_cnt': len(recentFindings),
            'vuln_webapp_cnt': len(vuln_webapp_set),
            'web_app_cnt': getWebAppCount(was_org_id),
            'high_rem_time' : highRemTime,
            'crit_rem_time' : critRemTime
        }
        insertWASVulnData(was_data)


    
#write a main function that takes in command line arguments
def main():
    """Main function."""
    fillData('05-01-2023')
    #fillFindings()
    #lastMonthData()
    #initializeWasMap()

if __name__ == "__main__":
    main()
