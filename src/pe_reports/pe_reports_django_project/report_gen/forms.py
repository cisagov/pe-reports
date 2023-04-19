from django import forms


class InfoFormExternal(forms.Form):
    """Create web form to take user input on report to be generated."""
    report_date = forms.DateField(label='Closing date of report period. *Format YYYY-MM_DD')

    output_directory = forms.CharField(label='Directory where the final PDF repots should be saved.', max_length=500)

    def __init__(self, *args, **kwargs):
        super(InfoFormExternal, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


class BulletinFormExternal(forms.Form):
    """Create web form to take user input on bulletin to be generated."""
    cybersix_id = forms.CharField(label='Cybersix Intel Item ID:')

    output_directory = forms.CharField(
        label='Directory where the final PDF reports should be saved.',
        max_length=500)

    def __init__(self, *args, **kwargs):
        super(BulletinFormExternal, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'



class CredsFormExternal(forms.Form):
    """Create web form to take user input on bulletin to be generated."""

    org_id = forms.CharField(label='Organization Cyhy ID:', max_length=100)
    breech_name = forms.CharField(label='Breech Name:', max_length=100)

    def __init__(self, *args, **kwargs):
        super(CredsFormExternal, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


class ScoreCardGenFormExternal(forms.Form):
    """Create web form to take user input on scorecard to be generated."""

    org_id = forms.CharField(label='Organization Cyhy ID:', max_length=100)
    month = forms.CharField(label='Month Run MM:', max_length=100)
    year = forms.CharField(label='Year Run, year format is YYYY:', max_length=100)
    # breech_name = forms.CharField(label='Breech Name:', max_length=100)

    def __init__(self, *args, **kwargs):
        super(ScoreCardGenFormExternal, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'



























# class InfoFormExternal(FlaskForm):
#     """Create web form to take user input on report to be generated."""
#
#     report_date = StringField(
#         "What is the report date? (Final day of the report period, either the 15th or last day of the month)"
#         "*format YYYY-MM-DD"
#     )
#     output_directory = StringField(
#         "The directory where the final PDF reports should be saved. "
#     )
#
#     submit = SubmitField("Submit", render_kw={"onclick": "loading()"})
#
#
# class BulletinFormExternal(FlaskForm):
#     """Create web form to take user input on bulletin to be generated."""
#
#     cybersix_id = StringField("Cybersix Intel Item ID:")
#     user_input = TextAreaField(
#         "Please provide an explanation of what was found in the post/intel_item."
#     )
#     # Using a distinct directory variable name to avoid validation errors when multiple forms are on the same page
#     output_directory1 = StringField("Output Directory:")
#     file_name = StringField("File Name?")
#     # Using a distinct submit variable name to avoid validation errors when multiple forms are on the same page
#     submit1 = SubmitField("Submit", render_kw={"onclick": "loading()"})
#
#
# class CredsFormExternal(FlaskForm):
#     """Create web form to take user input on bulletin to be generated."""
#
#     org_id = StringField("Organization Cyhy ID:")
#     breach_name = StringField("Breach Name:")
#     # Using a distinct submit variable name to avoid validation errors when multiple forms are on the same page
#     submit2 = SubmitField("Submit", render_kw={"onclick": "loading()"})
