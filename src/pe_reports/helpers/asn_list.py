import requests
import ipaddress
from pe_reports.data.db_query import insertServiceIPs
def main():
    akamaiCidrLinks = "https://raw.githubusercontent.com/SecOps-Institute/Akamai-ASN-and-IPs-List/master/akamai_ip_cidr_blocks.lst"
    request = requests.get(akamaiCidrLinks)
    lines = request.text.splitlines()
    for line in lines:
        firstIP,mask = line.split('/')
        serviceDict = {
            "network":line,
            'service_provider':'Akamai',
            'first_addr':firstIP,
            'last_addr':str(ipaddress.IPv4Address(firstIP) + (2**(32-int(mask)))-1)
        }
        print("inserting: ",serviceDict)
        insertServiceIPs(serviceDict)
        print("done")
        #100 000 queries takes 5 minutes
        
        
        
    
        
        
        
        
    
   

    
if __name__ == "__main__":
    main()
    