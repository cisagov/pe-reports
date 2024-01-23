"""Function for accessing the bulk WhoisXML API."""
# Standard Python Libraries
import json
from retry import retry
import requests
from time import sleep

# cisagov Libraries
from pe_reports.data.config import whois_xml_api_key


url = "https://www.whoisxmlapi.com/BulkWhoisLookup/bulkServices/"
whois_api = whois_xml_api_key()


def sendIPS(ip_list: list) -> str:
    """Sends a list of domains to WhoisXML API and retuern the requestID"""
    send_url = url + "bulkWhois"
    headers = {"Content-Type": "application/json"}
    body = {
        "apiKey": whois_api,
        "domains": ip_list,
        "outputFormat": "JSON",
    }
    response = requests.post(send_url, headers=headers, json=body)
    if response.status_code == 200:
        # print("Successful API call")
        responseJson = json.loads(response.text)
        # print("Bulk API found invalid domains for : {list}".format(list=responseJson['invalidDomains']))
        return responseJson['requestId']
    else:
        print("Unsuccessful API call")
        return ""


@retry(exceptions=requests.exceptions.RequestException, tries=10, delay=5)
def getDomains(requestId: str, index: int, blockSize: int) -> list:
    """Fetches domains from whoisXML using requestid and returns a list of blockSize amount of records."""
    get_url = url + "getRecords"
    headers = {"Content-Type": "application/json"}
    body = {
        "apiKey": whois_api,
        "requestId": requestId,
        "maxRecords": blockSize,  # how many records to get
        "startIndex": index,  # index to start getting those records
        "outputFormat": "JSON",
        "ip": 1
    }
    response = requests.post(get_url, headers=headers, json=body)
    if response.status_code != 200:
        response.raise_for_status()  # Will trigger a retry if status code isn't 200

    try:
        responseJson = response.json()
    except requests.exceptions.JSONDecodeError:
        print("Failed to parse the response to a JSON. Retrying...")
        raise  # Will trigger a retry

    recordsLeft = responseJson['recordsLeft']
    if responseJson['recordsProcessed'] < min(index + blockSize,
                                              responseJson["totalRecords"]):
        print(
            "Records requested still processing, {recordsLeft} records left, trying again".format(
                recordsLeft=recordsLeft))
        sleep(5)  # Delay before the next iteration
        raise Exception("Records still processing")  # Will trigger a retry

    return responseJson['whoisRecords']


def passthrough(ip_list):
    ips = ip_list
    requestId = sendIPS(ips)
    returnList = []
    whoisRecords = getDomains(requestId, 1, 10)
    for record in whoisRecords:
        try:
            reg = str(record['whoisRecord']['registryData']['registrant'])
            admin = str(
                record['whoisRecord']['registryData']['administrativeContact'])
            technical = str(
                record['whoisRecord']['registryData']['technicalContact'])
        except KeyError:
            reg, admin, technical = "None Found.", "None Found.", "None Found."
        ipEntry = {
            'ip': record['domainName'],
            'registrant': reg,
            'administrativeContact': admin,
            'technicalContact': technical
        }
        returnList.append(ipEntry)
        return returnList


