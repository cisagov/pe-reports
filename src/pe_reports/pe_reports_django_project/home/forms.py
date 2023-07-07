# Third-Party Libraries
from decouple import config
from django import forms
from django.contrib import messages
from django.contrib.auth.models import User
import requests

from .models import TeamMembers, WeeklyStatuses


class GatherStakeholderForm(forms.Form):
    cust = forms.CharField(label="Customer", max_length=500, required=True)

    custDomainAliases = forms.CharField(label="Domain Aliases", max_length=500)

    custRootDomain = forms.CharField(label="Customer Root Domain", max_length=500)

    custExecutives = forms.CharField(label="Customer Executives", max_length=500)

    def __init__(self, *args, **kwargs):
        super(GatherStakeholderForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"


class WeeklyStatusesForm(forms.Form):
    """Create web form to take user input on bulletin to be generated."""

    url = "https://api.github.com/repos/cisagov/pe-reports/issues?per_page=100&state=open&page=1"

    theuserIssues = forms.ChoiceField(
        label="",
        choices=[],
        required=True,
        widget=forms.Select(attrs={"id": "theuserIssues"}),
    )

    key_accomplishments = forms.CharField(
        label="Key accomplishments. Make commma separated list",
        widget=forms.Textarea(
            attrs={
                "rows": "2",
                "placeholder": "Use the dropdown "
                "to select an issue"
                " or type your Issue "
                "in format Issue"
                " - <Issue#>:.",
                "id": "key_accomplishments",
            }
        ),
    )

    ongoing_task = forms.CharField(
        label="Ongoing Tasks", widget=forms.Textarea(attrs={"rows": "2"})
    )

    upcoming_task = forms.CharField(
        label="Upcoming Tasks", widget=forms.Textarea(attrs={"rows": "2"})
    )

    obstacles = forms.CharField(
        label="Obstacles or Active Blockers", widget=forms.Textarea(attrs={"rows": "2"})
    )

    non_standard_meeting = forms.CharField(
        label="Non-standard meetings", widget=forms.Textarea(attrs={"rows": "2"})
    )

    deliverables = forms.CharField(
        label="Deliverables", widget=forms.Textarea(attrs={"rows": "2"})
    )

    pto_time = forms.CharField(
        label="Upcoming PTO", widget=forms.Textarea(attrs={"rows": "2"})
    )

    def __init__(self, *args, user=None, request=None, **kwargs):
        super(WeeklyStatusesForm, self).__init__(*args, **kwargs)
        self.current_user = user
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"

        print(user)
        if self.current_user and self.current_user.is_authenticated:
            theGHUsersname = TeamMembers.objects.filter(
                team_member_fname=self.current_user.first_name
            )
            user_issues_dict = getGHUsers(self.url, theGHUsersname[0].team_member_ghID)
            if user_issues_dict:
                pass

            else:
                messages.warning(request, "The user has not been assigned any issues. ")
                return HttpResponseRedirect("/weekly_status/")
            user_issues = user_issues_dict.get(theGHUsersname[0].team_member_ghID, [])
            choices = [(issue, issue) for issue in user_issues]
            self.fields["theuserIssues"].choices = choices


class UpdateWeeklyStatusesForm(forms.Form):
    """Create web form to take user input on bulletin to be generated."""

    url = "https://api.github.com/repos/cisagov/pe-reports/issues?per_page=100&state=open&page=1"

    updatetheuserIssues = forms.ChoiceField(
        label="",
        choices=[],
        required=True,
        widget=forms.Select(attrs={"id": "updatetheuserIssues"}),
    )

    updatekey_accomplishments = forms.CharField(
        label="Key accomplishments. Make commma separated list",
        widget=forms.Textarea(
            attrs={
                "rows": "2",
                "placeholder": "Use the dropdown "
                "to select an issue"
                " or type your Issue "
                "in format Issue"
                " - <Issue#>:.",
                "id": "updatekey_accomplishments",
            }
        ),
    )

    updateongoing_task = forms.CharField(
        label="Ongoing Tasks", widget=forms.Textarea(attrs={"rows": "2"})
    )

    updateupcoming_task = forms.CharField(
        label="Upcoming Tasks", widget=forms.Textarea(attrs={"rows": "2"})
    )

    updateobstacles = forms.CharField(
        label="Obstacles or Active Blockers", widget=forms.Textarea(attrs={"rows": "2"})
    )

    updatenon_standard_meeting = forms.CharField(
        label="Non-standard meetings", widget=forms.Textarea(attrs={"rows": "2"})
    )

    updatedeliverables = forms.CharField(
        label="Deliverables", widget=forms.Textarea(attrs={"rows": "2"})
    )

    updatepto_time = forms.CharField(
        label="Upcoming PTO", widget=forms.Textarea(attrs={"rows": "2"})
    )

    def __init__(self, *args, user=None, request=None, **kwargs):
        super(UpdateWeeklyStatusesForm, self).__init__(*args, **kwargs)
        self.current_user = user
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"

        print(user)
        if self.current_user and self.current_user.is_authenticated:
            theGHUsersname = TeamMembers.objects.filter(
                team_member_fname=self.current_user.first_name
            )
            user_issues_dict = getGHUsers(self.url, theGHUsersname[0].team_member_ghID)
            if user_issues_dict:
                pass

            else:
                messages.warning(request, "The user has not been assigned any issues. ")
                return HttpResponseRedirect("/weekly-status-form-only/")
            user_issues = user_issues_dict.get(theGHUsersname[0].team_member_ghID, [])
            choices = [(issue, issue) for issue in user_issues]
            self.fields["updatetheuserIssues"].choices = choices

    def save(self, user):
        if self.is_valid():
            weekly_status = WeeklyStatuses.objects.filter(
                user_status=user.first_name
            ).latest("week_ending")
            # update the fields of weekly_status from self.cleaned_data
            weekly_status.key_accomplishments = self.cleaned_data.get(
                "updatekey_accomplishments"
            )
            weekly_status.ongoing_task = self.cleaned_data.get("updateongoing_task")
            weekly_status.upcoming_task = self.cleaned_data.get("updateupcoming_task")
            weekly_status.obstacles = self.cleaned_data.get("updateobstacles")
            weekly_status.non_standard_meeting = self.cleaned_data.get(
                "updatenon_standard_meeting"
            )
            weekly_status.deliverables = self.cleaned_data.get("updatedeliverables")
            weekly_status.pto_time = self.cleaned_data.get("updatepto_time")
            # don't forget to save
            weekly_status.save()
        else:
            raise ValueError("Invalid form data")


def getGHUsers(url, user):
    """Get all GitHub issues for a user."""

    usersIssues = {}
    issueNames = []
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {config('access_tokenGH')}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    response = requests.get(url, headers=headers).json()

    for x in response:
        issueNumber = x["number"]
        issueTitle = x["title"]
        issueAssignee = x["user"]["login"]

        if issueAssignee == user and x is not None:

            issueNames.append("Issue - " + str(issueNumber) + ": ")
            usersIssues[issueAssignee] = issueNames

    return usersIssues
