"""Django home views."""
# Standard Python Libraries
from datetime import datetime, timedelta
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import glob
import json
import logging
import os
import re
import traceback

# Third-Party Libraries
import boto3
from botocore.exceptions import ClientError
from bs4 import BeautifulSoup
from decouple import config
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core import serializers
from django.http import (
    HttpResponse,
    HttpResponseNotFound,
    HttpResponseRedirect,
    JsonResponse,
)
from django.shortcuts import render
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import TemplateView
from django.views.generic.edit import FormView
from docxtpl import DocxTemplate
import pandas as pd
import requests
import spacy

# cisagov Libraries
from pe_asm.helpers.enumerate_subs_from_root import get_subdomains
from pe_asm.helpers.fill_cidrs_from_cyhy_assets import fill_cidrs
from pe_asm.helpers.link_subs_and_ips_from_ips import connect_subs_from_ips
from pe_asm.helpers.link_subs_and_ips_from_subs import connect_ips_from_subs
from pe_asm.helpers.shodan_dedupe import dedupe
from pe_reports.data.db_query import (
    check_org_exists,
    get_cidrs_and_ips,
    insert_roots,
    query_roots,
    set_org_to_demo,
    set_org_to_report_on,
)
from pe_source.data.sixgill.api import setNewCSGOrg

from .forms import (
    GenerateWeeklyStatusReportingForm,
    PeBulkUpload,
    UpdateWeeklyStatusesForm,
    WeeklyStatusesForm,
)

# TODO: Figure out circular referance on import
# from pe_source.data.sixgill.api import setOrganizationUsers, \
#     setOrganizationDetails
from .models import Organizations, WeeklyStatuses

LOGGER = logging.getLogger(__name__)

MAILER_ARN = os.environ.get("MAILER_ARN")


# Create your views here.


def getUserKey():
    """Get a users API key."""
    urlIDs = "http://127.0.0.1:8089/apiv1/get_key"
    payload = json.dumps({"refresh_token": f'{config("USER_REFRESH_TOKEN")}'})
    headers = {
        "Content-Type": "application/json",
    }

    response = requests.post(urlIDs, headers=headers, data=payload).json()

    return response


#
#
theCurrentUserKey = getUserKey()
# print(f'The current key is {theCurrentUserKey}')
theSavedUserKey = config("API_KEY")


# # print(f'The saved key is {theSavedUserKey}')
#
#
def updateAPIKey(theSavedUserKey, theCurrentUserKey):
    """Update API key."""
    if theSavedUserKey == theCurrentUserKey:
        print("The keys match and nothing happened. ")
    else:
        try:
            script_directory = os.path.dirname(os.path.realpath(__name__))
            print(script_directory)
            env_file_path = os.path.join(script_directory, ".env")
            with open(env_file_path) as f:
                f.seek(0)
                data = f.read()
                dataReplaced = data.replace(theSavedUserKey, theCurrentUserKey)
                print("Reading and replacing api key.")
            with open(env_file_path, "w") as f:
                if theSavedUserKey in data:
                    print("The apiKey has been updated.")
                    f.write(dataReplaced)
            return theCurrentUserKey
        except Exception:
            print("Failed to open and write new file.")


@login_required
def index(request):
    """Render index page."""
    allUsers = Organizations.objects.filter(name="EAC")
    # output = '<br>'.join([c.username for c in customers])
    users = {"user": allUsers}
    return render(request, "index.html", users)


@login_required
def home(request):
    """Render home page."""
    try:
        return render(request, "home.html")
    except Exception:
        return HttpResponseNotFound("Nothing found")


def create_word_document(request):
    """Create a word document."""
    accomplishments_list = []
    ongoing_tasks_list = []
    upcoming_tasks_list = []
    obstacles_list = []
    non_standard_meeting_list = []
    deliverables_list = []
    pto_list = []

    # Get the current week ending date
    current_date = datetime.now()
    days_to_week_end = (4 - current_date.weekday()) % 7
    week_ending_date = current_date + timedelta(days=days_to_week_end)
    reformatted_week_ending_date = week_ending_date.strftime("%m-%d-%Y")

    # Create a Document object
    # doc = Document()

    weeklyInfo = WeeklyStatuses.objects.filter(week_ending=week_ending_date)

    # Serialize the queryset to JSON
    serialized_data = serializers.serialize("json", weeklyInfo)

    # Load the serialized data into a JSON object
    json_data = json.loads(serialized_data)

    # print(json_data)
    # Iterate through the JSON object and set variables from the fields
    for status in json_data:
        accomplishments = status["fields"]["key_accomplishments"]
        ongoing_tasks = status["fields"]["ongoing_task"]
        upcoming_tasks = status["fields"]["upcoming_task"]
        obstacles = status["fields"]["obstacles"]
        non_standard_meeting = status["fields"]["non_standard_meeting"]
        deliverables = status["fields"]["deliverables"]
        pto = status["fields"]["pto"]
        # week_ending = status["fields"]["week_ending"]
        the_current_user = status["fields"]["user_status"]
        # statusComplete = status["fields"]["statusComplete"]

        # Append each status to their respective list
        if accomplishments not in accomplishments_list:
            split_data = re.split(r",\s+(?=ISSUE\s*-\s*\d+:)", accomplishments)

            for item in split_data:
                if item:
                    accomplishments_list.append(item)

        if ongoing_tasks not in ongoing_tasks_list:
            split_data = re.split(r",\s+(?=ISSUE\s*-\s*\d+:)", ongoing_tasks)

            for item in split_data:
                if item:
                    ongoing_tasks_list.append(ongoing_tasks)
        if upcoming_tasks not in upcoming_tasks_list:
            split_data = re.split(r",\s+(?=ISSUE\s*-\s*\d+:)", upcoming_tasks)

            for item in split_data:
                if item:
                    upcoming_tasks_list.append(upcoming_tasks)
        if obstacles not in obstacles_list:
            split_data = re.split(r",\s+(?=ISSUE\s*-\s*\d+:)", obstacles)

            for item in split_data:
                if item:
                    obstacles_list.append(obstacles)
        if non_standard_meeting not in non_standard_meeting_list:
            split_data = re.split(r",\s+(?=ISSUE\s*-\s*\d+:)", non_standard_meeting)

            for item in split_data:
                if item:
                    non_standard_meeting_list.append(non_standard_meeting)
        if deliverables not in deliverables_list:
            split_data = re.split(r",\s+(?=ISSUE\s*-\s*\d+:)", deliverables)

            for item in split_data:
                if item:
                    deliverables_list.append(deliverables)
        if pto not in pto_list:
            split_data = re.split(r",\s+(?=ISSUE\s*-\s*\d+:)", pto)

            for item in split_data:
                if item:
                    pto_list.append(pto)

        # Load the template
        template = DocxTemplate(
            "/Users/duhnc/Desktop/allInfo/"
            "pe-reports-apiextended/src/pe_reports/"
            "pe_reports_django_project/home/"
            "PEWeeklyStatusReportTemplate.docx"
        )

        # Define the values to insert into the template, including a list of tasks
        context = {
            "user": the_current_user.capitalize(),
            "week_ending": reformatted_week_ending_date,
            "accomplishments_list": accomplishments_list,
            "ongoing_tasks_list": ongoing_tasks_list,
            "upcoming_tasks_list": upcoming_tasks_list,
            "obstacles_list": obstacles_list,
            "non_standard_meeting_list": non_standard_meeting_list,
            "deliverables_list": deliverables_list,
            "pto_list": pto_list,
        }

        # Render the template with the context
        template.render(context)

        # Save the rendered document as a new Word file
        template.save(
            "/Users/duhnc/Desktop/allInfo/pe-reports-apiextended/"
            "src/pe_reports/pe_reports_django_project/home/"
            "statusReportArchive/"
            "weeklyStatus_%s.docx" % week_ending_date
        )

    messages.success(request, "The weekly status report has been created.")
    return HttpResponse("Word document created successfully.")


def email_notification(request):
    """Email notification to notify the user that the status has been submitted."""
    # TODO - Add the email notification to nofity the user that
    #  the status has been not been submitted


class FetchWeeklyStatusesView(View):
    """Fetch the weekly statuses from the API and pass to Weekly Statuses template."""

    updateAPIKey(theSavedUserKey, theCurrentUserKey)

    def get(self, request, *args, **kwargs):
        """Get weekly status views."""
        url = "http://127.0.0.1:8089/apiv1/fetch_weekly_statuses"
        headers = {
            "Content-Type": "application/json",
            "access_token": f'{config("API_KEY")}',
        }

        try:
            response = requests.post(url, headers=headers)
            response.raise_for_status()  # Raise an exception if the response contains an HTTP error status
            data = response.json()
            return JsonResponse(data, safe=False)

        except requests.exceptions.HTTPError as errh:
            LOGGER.error(errh)
        except requests.exceptions.ConnectionError as errc:
            LOGGER.error(errc)
        except requests.exceptions.Timeout as errt:
            LOGGER.error(errt)
        except requests.exceptions.RequestException as err:
            LOGGER.error(err)
        except json.decoder.JSONDecodeError as err:
            LOGGER.error(err)

        # Return an error JsonResponse if an exception occurs
        return JsonResponse({"error": "Failed to fetch weekly statuses"}, status=400)


def send_email_with_attachment(
    subject,
    body_text,
    from_email,
    to_emails,
    attachment,
    aws_region="us-east-1",
    cc_emails=None,
    bcc_emails=None,
    body_html=None,
):
    """Send email with attachment."""
    # Create a new SES resource and specify a region.
    session = boto3.Session(profile_name="cool-dns-sessendemail-cyber.dhs.gov")
    client = session.client("ses", region_name=aws_region)

    # Assume role to use mailer
    sts_client = boto3.client("sts")
    assumed_role_object = sts_client.assume_role(
        RoleArn=MAILER_ARN, RoleSessionName="AssumeRoleSession1"
    )
    credentials = assumed_role_object["Credentials"]

    ses_client = boto3.client(
        "ses",
        region_name="us-east-1",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )

    LOGGER.info(ses_client)

    # Create a multipart/mixed parent container.
    msg = MIMEMultipart("mixed")
    # Add subject, from and to lines.
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_emails
    msg["Cc"] = ", ".join(cc_emails) if cc_emails is not None else ""
    msg["Bcc"] = ", ".join(bcc_emails) if bcc_emails is not None else ""

    # Create a multipart/alternative child container.
    msg_body = MIMEMultipart("alternative")

    # Encode the text and HTML content and set the character encoding. This step is
    # necessary if you're sending a message with characters outside the ASCII range.
    textpart = MIMEText(body_text.encode("utf-8"), "plain", "utf-8")
    msg_body.attach(textpart)

    if body_html is not None:
        htmlpart = MIMEText(body_html.encode("utf-8"), "html", "utf-8")
        msg_body.attach(htmlpart)

    # Define the attachment part and encode it using MIMEApplication.
    att = MIMEApplication(open(attachment, "rb").read())

    # Add a header to tell the email client to treat this part as an attachment,
    # and to give the attachment a name.
    att.add_header(
        "Content-Disposition", "attachment", filename=os.path.basename(attachment)
    )

    # Attach the multipart/alternative child container to the multipart/mixed
    # parent container.
    msg.attach(msg_body)

    # Add the attachment to the parent container.
    msg.attach(att)

    print(f"From: {msg['From']}")
    print(f"To: {msg['To']}")
    print(f"Cc: {msg['Cc']}")
    print(f"Bcc: {msg['Bcc']}")

    try:
        # Provide the contents of the email.
        response = client.send_raw_email(
            Source=msg["From"],
            Destinations=[msg["To"]],
            RawMessage={
                "Data": msg.as_string(),
            },
        )
    # Display an error if something goes wrong.
    except ClientError as e:
        print(e.response["Error"]["Message"] + " The email was not sent.")
    else:
        print("Email sent! Message ID:"),
        print(response["MessageId"])


class StatusView(TemplateView):
    """Status view class."""

    template_name = "weeklyStatus.html"


class StatusForm(LoginRequiredMixin, FormView):
    """Status form class."""

    form_class = WeeklyStatusesForm
    second_form_class = GenerateWeeklyStatusReportingForm
    template_name = "weeklyStatus.html"
    form_only_template_name = "weeklyStatusFormOnly.html"
    status_report_archive_dir = os.path.join(
        settings.BASE_DIR, "home/statusReportArchive"
    )
    print(f"The file dir is {status_report_archive_dir}")
    filesWSR = glob.glob(os.path.join(status_report_archive_dir, "*.docx"))
    # Check if the list of files is empty
    if not filesWSR:
        print("No files in directory")
    else:
        most_recent_file = max(filesWSR, key=os.path.getctime)
        print(most_recent_file)

    success_url = reverse_lazy("weekly_status")

    def get_form_kwargs(self):
        """Get form arguments."""
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def get_context_data(self, **kwargs):
        """Get context data."""
        context = super().get_context_data(**kwargs)
        context["second_form"] = self.second_form_class()
        return context

    def get(self, request, *args, **kwargs):
        """Call get request."""
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            form = self.form_class()
            form_html = render_to_string(
                self.form_only_template_name, {"form": form}, request=request
            )
            return JsonResponse({"form_html": form_html})
        else:
            return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        """Call post request."""
        form = self.get_form()
        second_form = self.second_form_class(request.POST)
        if form.is_valid() or second_form.is_valid():
            return self.form_valid(form, second_form)
        else:
            return self.form_invalid(form, second_form)

    def form_valid(self, form, second_form):
        """Check if form is valid."""
        if form.is_valid():
            current_date = datetime.now()
            days_to_week_end = (4 - current_date.weekday()) % 7
            week_ending_date = current_date + timedelta(days=days_to_week_end)

            key_accomplishments = form.cleaned_data["key_accomplishments"].upper()
            ongoing_task = form.cleaned_data["ongoing_task"].upper()
            upcoming_task = form.cleaned_data["upcoming_task"].upper()
            obstacles = form.cleaned_data["obstacles"].upper()
            non_standard_meeting = form.cleaned_data["non_standard_meeting"].upper()
            deliverables = form.cleaned_data["deliverables"].upper()
            pto = form.cleaned_data["pto_time"].upper()

            weeklyStatus, created = WeeklyStatuses.objects.get_or_create(
                week_ending=week_ending_date,
                user_status=self.request.user.first_name,
                defaults={
                    "key_accomplishments": key_accomplishments,
                    "ongoing_task": ongoing_task,
                    "upcoming_task": upcoming_task,
                    "obstacles": obstacles,
                    "non_standard_meeting": non_standard_meeting,
                    "deliverables": deliverables,
                    "pto": pto,
                },
            )

            if not created:
                weeklyStatus.key_accomplishments = key_accomplishments
                weeklyStatus.ongoing_task = ongoing_task
                weeklyStatus.upcoming_task = upcoming_task
                weeklyStatus.obstacles = obstacles
                weeklyStatus.non_standard_meeting = non_standard_meeting
                weeklyStatus.deliverables = deliverables
                weeklyStatus.pto = pto
                weeklyStatus.save()

            messages.success(self.request, "The weekly status was saved successfully.")

        if second_form.is_valid():
            toemail = "craig.duhn@associates.cisa.dhs.gov"
            fromemail = "pe_automation@cisa.dhs.gov"
            date = second_form.cleaned_data["date"]
            create_word_document(date, self.request)
            # theawsregion = "us-east-1"
            send_email_with_attachment(
                "WSR Attached",
                "The WSR is attached",
                from_email=fromemail,
                to_emails=toemail,
                attachment=self.most_recent_file,
            )

        return super().form_valid(form)


class updateStatusView(TemplateView):
    """Class to update status view."""

    template_name = "weeklyStatusFormOnly.html"


class updateStatusForm(LoginRequiredMixin, FormView):
    """Class to update Status form."""

    form_class = UpdateWeeklyStatusesForm
    template_name = "weeklyStatusFormOnly.html"
    form_only_template_name = "weeklyStatusFormOnly.html"

    success_url = reverse_lazy("weekly_status")

    def get_form_kwargs(self):
        """Get form arguments."""
        kwargs = super(StatusForm, self).get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def get(self, request, *args, **kwargs):
        """Call form get method."""
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            form = self.form_class()
            form_html = render_to_string(
                self.form_only_template_name, {"form": form}, request=request
            )
            return JsonResponse({"form_html": form_html})
        else:
            return super().get(request, *args, **kwargs)

    def form_valid(self, form):
        """Validate form."""
        current_date = datetime.now()
        days_to_week_end = (4 - current_date.weekday()) % 7
        week_ending_date = current_date + timedelta(days=days_to_week_end)

        key_accomplishments = form.cleaned_data["key_accomplishments"].upper()
        ongoing_task = form.cleaned_data["ongoing_task"].upper()
        upcoming_task = form.cleaned_data["upcoming_task"].upper()
        obstacles = form.cleaned_data["obstacles"].upper()
        non_standard_meeting = form.cleaned_data["non_standard_meeting"].upper()
        deliverables = form.cleaned_data["deliverables"].upper()
        pto = form.cleaned_data["pto_time"].upper()

        weeklyStatus, created = WeeklyStatuses.objects.get_or_create(
            week_ending=week_ending_date,
            user_status=self.request.user.first_name,
            defaults={
                "key_accomplishments": key_accomplishments,
                "ongoing_task": ongoing_task,
                "upcoming_task": upcoming_task,
                "obstacles": obstacles,
                "non_standard_meeting": non_standard_meeting,
                "deliverables": deliverables,
                "pto": pto,
            },
        )

        if not created:
            weeklyStatus.key_accomplishments = key_accomplishments
            weeklyStatus.ongoing_task = ongoing_task
            weeklyStatus.upcoming_task = upcoming_task
            weeklyStatus.obstacles = obstacles
            weeklyStatus.non_standard_meeting = non_standard_meeting
            weeklyStatus.deliverables = deliverables
            weeklyStatus.pto = pto
            weeklyStatus.save()

        messages.success(self.request, "The weekly status was saved successfully.")
        return super().form_valid(form)


class WeeklyStatusesFormOnlyView(updateStatusForm):
    """Weekly status form only view."""

    template_name = "weeklyStatusFormOnly.html"

    def get(self, request, *args, **kwargs):
        """Get form view."""
        # Fetch the most recent instance of the model for this user
        weekly_status = WeeklyStatuses.objects.filter(
            user_status=request.user.first_name
        ).latest("week_ending")

        # Initialize the form with the instance's data
        form = self.form_class(
            initial={
                "updatekey_accomplishments": weekly_status.key_accomplishments,
                "updateuser_status": self.request.user.first_name,
                "updateongoing_task": weekly_status.ongoing_task,
                "updateupcoming_task": weekly_status.upcoming_task,
                "updateobstacles": weekly_status.obstacles,
                "updatenon_standard_meeting": weekly_status.non_standard_meeting,
                "updatedeliverables": weekly_status.deliverables,
                "updatepto_time": weekly_status.pto,
            },
            user=request.user,
        )

        form_html = render_to_string(
            self.template_name, self.get_context_data(form=form), request=request
        )
        return JsonResponse({"form_html": form_html})

    def post(self, request, *args, **kwargs):
        """Post Weekly Status."""
        print("Getting to update post at WeeklyStatusesFormOnlyView")
        form = self.form_class(request.POST, user=request.user)
        if form.is_valid():
            # save the form
            form.save(user=request.user)

            messages.success(request, "The weekly status was updated successfully.")
            return HttpResponseRedirect("/weekly_status/")
        else:
            messages.error(request, "Invalid form data.")
            return render(request, self.template_name, {"form": form})


class FetchUserWeeklyStatusesView(View):
    """Fetch the weekly statuses from the API and pass to Weekly Statuses template."""

    updateAPIKey(theSavedUserKey, theCurrentUserKey)

    def get(self, request, *args, **kwargs):
        """Call get method for form."""
        url = "http://127.0.0.1:8089/apiv1/fetch_user_weekly_statuses/"
        headers = {
            "Content-Type": "application/json",
            "access_token": f'{config("API_KEY")}',
        }
        payload = json.dumps({"user_fname": request.user.first_name})

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()  # Raise an exception if the response contains an HTTP error status
            data = response.json()
            return JsonResponse(data, safe=False)

        except requests.exceptions.HTTPError as errh:
            LOGGER.error(errh)
        except requests.exceptions.ConnectionError as errc:
            LOGGER.error(errc)
        except requests.exceptions.Timeout as errt:
            LOGGER.error(errt)
        except requests.exceptions.RequestException as err:
            LOGGER.error(err)
        except json.decoder.JSONDecodeError as err:
            LOGGER.error(err)

        # Return an error JsonResponse if an exception occurs
        return JsonResponse({"error": "Failed to fetch weekly statuses"}, status=400)


def theExecs(URL):
    """Fetch executives from about page."""
    # Scrape the page with Beautiful Soup
    nlp = spacy.load("en_core_web_lg")
    page = requests.get(URL).text
    soup = BeautifulSoup(page, "lxml")
    body = soup.body.text
    body = body.replace("\n", " ")
    body = body.replace("\t", " ")
    body = body.replace("\r", " ")
    body = body.replace("\xa0", " ")

    # Use NLP to locate the executive names and append to list
    exec_list = []
    doc = nlp(body)
    for ent in doc.ents:
        exec_list.append((ent.label_, ent.text))

    # Clean up exec list
    final_exec_list = []
    regex_pattern = re.compile(r"[@_'’!#\-$%^&*()<>?/\|}{~:]")
    for hy in exec_list:
        if ("PERSON" in hy) and (hy[1] not in final_exec_list) and (len(hy[1]) < 50):
            if not regex_pattern.search(hy[1]) and len(hy[1].split()) > 1:
                person = hy[1].split("  ")
                if len(person) <= 1:
                    final_exec_list.append(hy[1])
    return final_exec_list


def add_stakeholders(request, orgs_df):
    """Add each stakeholder to P&E infrastructure."""
    count = 0
    for org_index, org_row in orgs_df.iterrows():
        # Check if org is in the P&E database
        org_exists = check_org_exists(org_row["org_code"])
        if not org_exists:
            LOGGER.info("%s doesn't exist in the P&E database", org_row["org_code"])
            messages.warning(
                request,
                "This org doesn't exist in the P&E database: %s " % org_row["org_code"],
            )
            continue

        try:
            LOGGER.info(f"Beginning to add {org_row['org_code']}")
            premium = org_row["premium"]
            # Set new org to report on
            if org_row["demo"] is True:
                new_org_df = set_org_to_demo(org_row["org_code"], premium)
            else:
                new_org_df = set_org_to_report_on(org_row["org_code"], premium)

            LOGGER.info(new_org_df)
            # Insert root domains
            LOGGER.info("Getting root domains:")
            insert_roots(new_org_df, org_row["root_domain"].split(","))
            LOGGER.info(org_row["root_domain"].split(","))

            # Enumerate and save subdomains
            roots = query_roots(new_org_df["organizations_uid"].iloc[0])
            get_subdomains(False, roots)
            LOGGER.info("Subdomains have been successfully added to the database.")

            # Fill the cidrs from cyhy assets
            LOGGER.info("Filling all cidrs:")
            fill_cidrs(new_org_df, False)
            LOGGER.info("Finished filling all cidrs.")

            # Connect to subs and IPs from subs table (only new orgs)
            LOGGER.info("Connecting IPs from Subs:")
            connect_ips_from_subs(False, new_org_df)
            LOGGER.info("Finished connecting subs/ips from subs.")

            # Connect subs and IPs from IPs table (only new orgs)
            LOGGER.info("Connecting Subs from IPs:")
            connect_subs_from_ips(False, new_org_df)
            LOGGER.info("Finished connecting subs/ips from IPs.")

            # TODO: Fix add to sixgill
            # Check if the org should be added to Cybersixgill
            if org_row["premium"] is True:
                # Get executives list by passing the about page URL
                LOGGER.info("Getting executives:")
                allExecutives = list(theExecs(org_row["exec_url"]))
                logging.info(allExecutives)

                # Insert org and all assets into Cybersixgill
                allValidIP = get_cidrs_and_ips(new_org_df["organizations_uid"].iloc[0])
                aliases = org_row["aliases"].split(",")
                LOGGER.info("Addind these assets to Cybersixgill:")
                LOGGER.info(org_row["org_code"])
                LOGGER.info(aliases)
                LOGGER.info(org_row["root_domain"].split(","))
                LOGGER.info(allValidIP)
                LOGGER.info(allExecutives)

                setNewCSGOrg(
                    org_row["org_code"],
                    aliases,
                    org_row["root_domain"].split(","),
                    allValidIP,
                    allExecutives,
                )

            # Run Shodan dedupe script
            LOGGER.info("Running Shodan dedupe:")
            dedupe(False, new_org_df)
            LOGGER.info("Finished running shodan dedupe.")

            LOGGER.info("Completely done with %s", org_row["org_code"])
            count += 1
        except Exception as e:
            LOGGER.info(e)
            LOGGER.error("%s failed.", org_row["org_code"])
            LOGGER.error(traceback.format_exc())
            continue
    LOGGER.info(f"Finished {count} orgs.")
    return count


class PeBulkUploadView(TemplateView):
    """CBV route to bulk upload page."""

    template_name = "stakeholder/stakeholder.html"
    form_class = PeBulkUpload


class PeBulkUploadForm(LoginRequiredMixin, FormView):
    """Upload P&E stakeholders through CSV."""

    form_class = PeBulkUpload
    template_name = "stakeholder/stakeholder.html"

    success_url = reverse_lazy("peBulkUpload")

    def form_valid(self, form):
        """Validate form data."""
        csv_file = form.cleaned_data["file"]

        df = pd.read_csv(csv_file.file)

        uploaded_columns = set(df.columns)
        LOGGER.info(uploaded_columns)

        required_columns = [
            "org_name",
            "org_code",
            "root_domain",
            "exec_url",
            "aliases",
            "premium",
            "demo",
        ]

        # Check needed columns exist
        # req_col = ""

        incorrect_col = []
        testtheList = [i for i in required_columns if i in uploaded_columns]
        # LOGGER.info(testtheList)

        if len(testtheList) == len(uploaded_columns):
            messages.success(self.request, "The file was uploaded successfully.")

            self.process_item(df)

            return super().form_valid(form)
        else:
            for col in required_columns:
                if col in uploaded_columns:
                    pass
                else:
                    incorrect_col.append(col)

            messages.warning(
                self.request,
                "A required column is missing"
                " from the uploaded CSV: %s " % incorrect_col,
            )
            return super().form_invalid(form)

    def process_item(self, df):
        """Upload each stakeholder into the P&E infrastructure."""
        LOGGER.info(df["org_code"])
        add_stakeholders(self.request, df)
