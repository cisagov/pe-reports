"""Tool for gathering information from OPM and DOTGOV and storing it in the PE database."""
import requests
import xml.etree.ElementTree as ET
import csv  
from pe_reports.data.db_query import get_org_uuid


def dotGovData():
    url = 'https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv'
    r = requests.get(url, allow_redirects=True)
    open('dotgov.csv', 'wb').write(r.content)
    
    opendotGov = open('dotgov.csv', 'r')
    csvReader = csv.reader(opendotGov)
    header = next(csvReader)
    for line in csvReader:
        
        rootDomainDict = {
            'organization_uid':get_org_uuid(line[3]),#this will fail for most because they arent exact matches
            'root_domain':line[0],
            'ip_address':None, #Assuming we are going to use whoisxmlapi to get this?
            'data_source_uid':'f7229dcc-98a9-11ec-a1c4-02589a36c9d7',#data source uid for dotgov
            'enumerate_subs': False #idk if this is going to be true or not
            }
        #after we are going to want to insert this data
        print(rootDomainDict['organization_uid'])
    

def opmData():
    url = "https://www.opm.gov/about-us/open-government/Data/Apps/agencies/agencies.xml?type=Cabinet%20Level%20Agencies"
    r = requests.get(url, allow_redirects=True)
    open('opm.xml', 'wb').write(r.content)
    tree = ET.parse('opm.xml')
    root = tree.getroot()
    cnt = 0
    
    
    #unsure what exactly to do with this data
    #i do know that we are going to insert this into the organziations database
    #sql """CREATE TABLE opm_map (
    #    org_id uuid PRIMARY KEY,
    #    opm_name text,
    #    parent_org_id uuid)

def main():
    dotGovData()

if __name__ == "__main__":
    main()