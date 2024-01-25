"""Script to go through all sub domains and check if they are active or not."""

# Third-Party Libraries
import requests

# cisagov Libraries
from pe_reports.data.config import whois_xml_api_key
from pe_reports.data.db_query import connect, query_all_subs


# function that uses whoisxml api to get status of domain
def get_domain_status(domain):
    """get_domain_status function."""
    api_key = whois_xml_api_key()
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=JSON"
    response = requests.get(url)
    print(response)
    """json_data = response.json()
    status = json_data['WhoisRecord']['registryData']['status']
    return status"""


def main():
    """Query orgs and run them through the enuemeration function."""
    orgs = query_all_subs(connect())
    print(orgs[0][1])


if __name__ == "__main__":
    main()
