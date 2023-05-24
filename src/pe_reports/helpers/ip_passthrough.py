"""Function for accessing the bulk WhoisXML API."""
import requests
import json
from time import sleep
from pe_reports.data.config import whois_xml_api_key
url = "https://www.whoisxmlapi.com/BulkWhoisLookup/bulkServices/"
whois_api = whois_xml_api_key()

def sendIPS(ip_list:list) -> str:
    """Sends a list of domains to WhoisXML API and retuern the requestID"""
    send_url = url + "bulkWhois"
    headers={"Content-Type" : "application/json"}
    body = {
        "apiKey": whois_api,
        "domains": ip_list,
        "outputFormat": "JSON",
    }
    response = requests.post(send_url,headers=headers,json=body)
    if response.status_code == 200:
        #print("Successful API call")
        responseJson = json.loads(response.text)
        #print("Bulk API found invalid domains for : {list}".format(list=responseJson['invalidDomains']))
        return responseJson['requestId']
    else:
        print("Unsuccessful API call")
        return ""

def getDomains(requestId:str,index:int,blockSize:int) -> list:
    """Fetches domains from whoisXML using requestid and returns a list of blockSize amount of records."""
    get_url = url + "getRecords"
    headers={"Content-Type" : "application/json"}
    body = {
        "apiKey": whois_api,
        "requestId": requestId, 
        "maxRecords": blockSize, #how many records to get
        "startIndex": index, #index to start getting those records
        "outputFormat": "JSON",
        "ip": 1
    }   
    response = requests.post(get_url,headers=headers,json=body)
    while response.status_code == 200:
        responseJson = json.loads(response.text)
        recordsLeft = responseJson['recordsLeft']
        if responseJson['recordsProcessed'] < min(index+blockSize,responseJson["totalRecords"]):
            print("Records requested still processing, {recordsLeft} records left, trying again".format(recordsLeft=recordsLeft))
            sleep(5)
            response = requests.post(get_url,headers=headers,json=body)
            continue
        return responseJson['whoisRecords']
    else:
        return ""
    

    
def passthrough(ip_list):
    ips = ip_list
    requestId = sendIPS(ips)
    returnList = []
    whoisRecords = getDomains(requestId,1,10)
    for record in whoisRecords:
        ipEntry = {
            'ip' : record['domainName'],
            'registrant' : str(record['whoisRecord']['registryData']['registrant']),
            'administrativeContact' : str(record['whoisRecord']['registryData']['administrativeContact']),   
            'technicalContact': str(record['whoisRecord']['registryData']['technicalContact'])
        }
        returnList.append(ipEntry)
        return returnList



