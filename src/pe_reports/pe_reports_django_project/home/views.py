# Built in packages
import logging
import json
import socket

# Third party packages
from django.views.generic import TemplateView
from django.views.generic.edit import FormView
from django.shortcuts import render
from django.http import HttpResponseNotFound, HttpResponseRedirect
from django.core.exceptions import ObjectDoesNotExist
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.contrib.auth import logout

from .models import Organizations
from .forms import GatherStakeholderForm, WeeklyStatusesForm
import requests

# cisagov Libraries

LOGGER = logging.getLogger(__name__)


# Create your views here.
def getAgencies(org_name):
    """Get all agency names from P&E database."""
    # global conn, cursor

    try:
        # params = config()
        #
        # conn = psycopg2.connect(**params)
        #
        # if conn:
        #     LOGGER.info(
        #         "There was a connection made to"
        #         "the database and the query was executed."
        #     )
        #
        #     cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        #
        #     query = "select organizations_uid,name from"
        #     " organizations where name='{}';"
        #
        #     cursor.execute(query.format(org_name))
        #
        #     result = cursor.fetchall()
        result = Organizations.objects.filter(name=org_name)
        resultDict = {}

        for row in result:
            # row[0] = org UUID
            # row[1] = org name
            resultDict[f"{row[0]}"] = f"{row[1]}"
        return resultDict

    except (Exception, ObjectDoesNotExist) as err:
        LOGGER.error("There was a problem logging into the psycopg database %s",
                     err)
    finally:
        # if conn is not None:
        #     cursor.close()
        #     conn.close()
        LOGGER.info("The connection/query was completed and closed.")

        return resultDict


def getSubdomain(domain):
    """Get all sub-domains from passed in root domain."""
    allsubs = []

    url = "https://domains-subdomains-discovery.whoisxmlapi.com/api/v1"
    payload = json.dumps(
        {
            "apiKey": f"{API_WHOIS}",
            "domains": {"include": [f"{domain}"]},
            "subdomains": {"include": ["*"], "exclude": []},
        }
    )
    headers = {"Content-Type": "application/json"}
    response = requests.request("POST", url, headers=headers, data=payload)
    data = response.json()

    subdomains = data["domainsList"]
    LOGGER.info(subdomains)

    subisolated = ""
    for sub in subdomains:

        if sub != f"www.{domain}":
            LOGGER.info(sub)
            subisolated = sub.rsplit(".")[:-2]
            LOGGER.info(
                "The whole sub is %s and the isolated sub is %s", sub,
                subisolated
            )
        allsubs.append(subisolated)

    return subdomains, allsubs


def getallsubdomainIPS(domain):
    """Get a list of IP addresses associated with a subdomain."""
    LOGGER.info("The domain at getallsubdomsinIPS is %s", domain)
    alladdresses = []
    for x in getSubdomain(domain)[0]:
        domainaddress = theaddress(x)
        if domainaddress not in alladdresses and domainaddress != "":
            alladdresses.append(domainaddress)
    return alladdresses


def theaddress(domain):
    """Get actual IP address of domain."""
    gettheAddress = ""
    try:
        gettheAddress = socket.gethostbyname(domain)
    except socket.gaierror:
        LOGGER.info("There is a problem with the domain that you selected")

    return gettheAddress


def setStakeholder(customer):
    """Insert customer into the P&E reports database."""
    global conn, cursor

    try:
        LOGGER.info("Starting insert into database...")

        params = config()

        conn = psycopg2.connect(**params)

        if conn:
            LOGGER.info(
                "There was a connection made to "
                "the database and the query was executed "
            )

            cursor = conn.cursor()

            cursor.execute(
                f"insert into organizations(name)" f"values('{customer}')")

            return True

    except (Exception, psycopg2.DatabaseError) as err:
        LOGGER.error("There was a problem logging into the psycopg database %s",
                     err)
        return False
    finally:
        if conn is not None:
            conn.commit()
            cursor.close()
            conn.close()
            LOGGER.info("The connection/query was completed and closed.")


def setCustRootDomain(customer, rootdomain, orgUUID):
    """Insert customer root domain into the PE-Reports database."""
    global conn, cursor

    try:
        LOGGER.info("Starting insert into database...")

        params = config()

        conn = psycopg2.connect(**params)

        if conn:
            LOGGER.info(
                "There was a connection made to "
                "the database and the query was executed "
            )

            cursor = conn.cursor()

            cursor.execute(
                f"insert into root_domains("
                f"organizations_uid,"
                f"organization_name,"
                f" root_domain)"
                f"values('{orgUUID}', '{customer}','{rootdomain}');"
            )
            return True

    except (Exception, psycopg2.DatabaseError) as err:
        LOGGER.error("There was a problem logging into the psycopg database %s",
                     err)
        return False
    finally:
        if conn is not None:
            conn.commit()
            cursor.close()
            conn.close()
            LOGGER.info("The connection/query was completed and closed.")


def setCustSubDomain(subdomain, rootUUID, rootname):
    """Insert customer into the PE-Reports database."""
    global conn, cursor

    try:

        LOGGER.info("Starting insert into database...")

        params = config()

        conn = psycopg2.connect(**params)

        if conn:

            LOGGER.info(
                "There was a connection made to "
                "the database and the query to "
                "insert the subdomains was executed "
            )

            cursor = conn.cursor()

            for sub in subdomain:
                cursor.execute(
                    f"insert into sub_domains("
                    f"sub_domain,"
                    f"root_domain_uid,"
                    f" root_domain)"
                    f"values('{sub}',"
                    f" '{rootUUID}',"
                    f"'{rootname}');"
                )
            return True

    except (Exception, psycopg2.DatabaseError) as err:
        LOGGER.error("There was a problem logging into the psycopg database %s",
                     err)
        return False
    finally:
        if conn is not None:
            conn.commit()
            cursor.close()
            conn.close()
            LOGGER.info("The connection/query was completed and closed.")


def setCustomerExternalCSG(
        customer, customerIP, customerRootDomain, customerSubDomain,
        customerExecutives
):
    """Insert customer not in cyhyDB into the PE-Reports database."""
    global conn, cursor

    iplist = []
    domainlist = []
    try:
        LOGGER.info("Starting insert into database...")

        params = config()

        conn = psycopg2.connect(**params)

        if conn:

            LOGGER.info(
                "There was a connection made to"
                " the database and the query was executed "
            )

            cursor = conn.cursor()

            for ip in customerIP:
                iplist.append(ip)

                cursor.execute(
                    f"insert into organizations(domain_name,"
                    f" domain_ip,"
                    f" date_saved) "
                    f"values('{customer}',"
                    f" '{ip}',"
                    f"'{thedateToday}');"
                )
            for domain in customerRootDomain:
                domainlist.append(domain)
                cursor.execute(
                    f"insert into domain_assets(domain_name,"
                    f" domain_ip,"
                    f" date_saved) "
                    f"values('{customer}',"
                    f" '{ip}', '{thedateToday}');"
                )

    except (Exception, psycopg2.DatabaseError) as err:
        LOGGER.error("There was a problem logging into the psycopg database %s",
                     err)
    finally:
        if conn is not None:
            conn.commit()
            cursor.close()
            conn.close()
            LOGGER.info("The connection/query was completed and closed.")

    return iplist


def setNewCSGOrg(newOrgName, orgAliases, orgdomainNames, orgIP, orgExecs):
    """Set a new stakeholder name at CSG."""
    newOrganization = json.dumps(
        {
            "name": f"{newOrgName}",
            "organization_commercial_category": "customer",
            "countries": ["worldwide"],
            "industries": ["Government"],
        }
    )
    url = "https://api.cybersixgill.com/multi-tenant/organization"

    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": f"Bearer {getToken()}",
    }

    response = requests.post(url, headers=headers, data=newOrganization).json()

    newOrgID = response["id"]

    if newOrgID:
        LOGGER.info("A new org_id was created: %s", newOrgID)

        setOrganizationUsers(newOrgID)
        setOrganizationDetails(newOrgID, orgAliases, orgdomainNames, orgIP,
                               orgExecs)

    return response


@login_required
def index(request):
    allUsers = Organizations.objects.filter(name='EAC')
    # output = '<br>'.join([c.username for c in customers])
    users = {
        "user": allUsers
    }
    return render(request, 'index.html', users)


@login_required
def home(request):
    try:
        return render(request, 'home.html')
    except:
        return HttpResponseNotFound('Nothing found')


@login_required
def stakeholder(request):
    try:
        if request.method == 'POST':
            LOGGER.info('Got to the stakeholder form')
            form = GatherStakeholderForm(request.POST)
            if form.is_valid():
                cust = form.cleaned_data['cust'].upper()
                custDomainAliases = form.cleaned_data[
                    'custDomainAliases'].split(
                    ",")
                custRootDomain = form.cleaned_data["custRootDomain"].split(",")
                custRootDomainValue = custRootDomain[0]
                custExecutives = form.cleaned_data["custExecutives"].split(",")
                allDomain = getAgencies(cust)
                allSubDomain = getSubdomain(custRootDomainValue)
                allValidIP = getallsubdomainIPS(custRootDomainValue)
                # print(custExecutives)

                try:

                    if cust not in allDomain.values():
                        messages.success(request,

                                         f"You successfully submitted a new"
                                         f" customer {cust}")

                        if setStakeholder(cust):
                            LOGGER.info("The customer %s was entered.", cust)
                            allDomain = list(getAgencies(cust).keys())[0]

                            if setCustRootDomain(cust, custRootDomainValue,
                                                 allDomain):
                                rootUUID = getRootID(allDomain)[cust]

                                LOGGER.info(
                                    "The root domain %s was entered at root_domains.",
                                    custRootDomainValue,
                                )
                                if allSubDomain:
                                    for subdomain in allSubDomain:
                                        if setCustSubDomain(subdomain, rootUUID,
                                                            cust):
                                            LOGGER.info(
                                                "The subdomains have been entered.")
                                            setNewCSGOrg(
                                                cust,
                                                custDomainAliases,
                                                custRootDomain,
                                                allValidIP,
                                                custExecutives,
                                            )

                    else:
                        messages.warning(request, f"The customer"
                                                  f" {cust} already exists.")

                except ValueError as e:
                    messages.warning(request,
                                     "The customer IP %s is not a valid IP, please try again.",
                                     "danger", e)
                    return HttpResponseRedirect("/stakeholder/")
                messages.success(request,
                                 "The new stakeholder has been inserted.d")
                return HttpResponseRedirect("/stakeholder/")



        else:
            form = GatherStakeholderForm()
        return render(request, 'stakeholder/stakeholder.html', {'form': form})


    except:
        return HttpResponseNotFound('Nothing found')


class StatusView(TemplateView):
    template_name = 'weeklyStatus.html'
    LOGGER.info('Got to Status')


class StatusForm(FormView):
    form_class = WeeklyStatusesForm
    template_name = 'weeklyStatus.html'

    success_url = reverse_lazy('weekly_status')

    def form_valid(self, form):
        theorgCount = form.cleaned_data['pto_time'].upper()
        LOGGER.info(f'The org count was {theorgCount}')

        return super().form_valid(form)
