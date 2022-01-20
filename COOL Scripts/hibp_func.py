"""Functions that call HIBP for breaches and credentials."""
# Standard Python Libraries
import time

# Third-Party Libraries
import pandas as pd
import requests

Emails_URL = "https://haveibeenpwned.com/api/v2/enterprisesubscriber/domainsearch/"
Breaches_URL = "https://haveibeenpwned.com/api/v2/breaches"
params = {"Authorization": "<<HIBP API KEY>>"}


def get_breaches():
    """Call HIBP api for breaches data."""
    breaches = requests.get(Breaches_URL, headers=params)
    breach_list = []
    if breaches.status_code == 200:
        jsonResponse = breaches.json()
        for line in jsonResponse:
            breach = {
                "breach_name": line["Name"],
                "breach_date": line["BreachDate"],
                "added_date": line["AddedDate"],
                "exposed_cred_count": line["PwnCount"],
                "modified_date": line["ModifiedDate"],
                "data_classes": line["DataClasses"],
                "description": line["Description"],
                "is_verified": line["IsVerified"],
                "is_fabricated": line["IsFabricated"],
                "is_sensitive": line["IsSensitive"],
                "is_retired": line["IsRetired"],
                "is_spam_list": line["IsSpamList"],
            }
            if "Passwords" in line["DataClasses"]:
                breach["password_included"] = True
            else:
                breach["password_included"] = False
            breach_list.append(breach)
        return pd.DataFrame(breach_list)
    else:
        print(breaches.text)


def get_emails(domain):
    """Call HIBP api for credentials for a provided subdomain."""
    run_failed = True
    counter = 0
    while run_failed:
        URL = Emails_URL + domain
        r = requests.get(URL, headers=params)
        status = r.status_code
        counter += 1
        if status == 200:
            return r.json()
        elif counter > 5:
            run_failed = False
        else:
            run_failed = True
            print(status)
            print(r.text)
            print(f"Trying to run on {domain} again")
            if status == 502:
                time.sleep(60 * 3)
