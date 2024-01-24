"""Create forms to use on the report gen page."""
# Third-Party Libraries
from django import forms


class InfoFormExternal(forms.Form):
    """Create web form to take user input on report to be generated."""

    report_date = forms.DateField(
        label="Closing date of report period. *Format YYYY-MM_DD"
    )

    output_directory = forms.CharField(
        label="Directory where the final PDF repots should be saved.", max_length=500
    )

    def __init__(self, *args, **kwargs):
        """Initialize report gen form."""
        super(InfoFormExternal, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"


class BulletinFormExternal(forms.Form):
    """Create web form to take user input on bulletin to be generated."""

    cybersix_id = forms.CharField(label="Cybersix Intel Item ID:")

    output_directory = forms.CharField(
        label="Directory where the final PDF reports should be saved.", max_length=500
    )

    def __init__(self, *args, **kwargs):
        """Initialize bulletin gen form."""
        super(BulletinFormExternal, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"


class CredsFormExternal(forms.Form):
    """Create web form to take user input on bulletin to be generated."""

    org_id = forms.CharField(label="Organization Cyhy ID:", max_length=100)
    breach_name = forms.CharField(label="Breach Name:", max_length=100)

    def __init__(self, *args, **kwargs):
        """Initialize cred breach gen form."""
        super(CredsFormExternal, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"


class ScoreCardGenFormExternal(forms.Form):
    """Create web form to take user input on scorecard to be generated."""

    org_id = forms.CharField(label="Organization Cyhy ID:", max_length=100)
    month = forms.CharField(label="Month Run MM:", max_length=100)
    year = forms.CharField(label="Year Run, year format is YYYY:", max_length=100)
    cancel_refresh = forms.BooleanField(label="Cancel view refresh", required=False)
    exclude_bods = forms.BooleanField(
        label="Exclude BOD data from scorecard", required=False
    )

    def __init__(self, *args, **kwargs):
        """Initialize scorecard gen form."""
        super(ScoreCardGenFormExternal, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"
