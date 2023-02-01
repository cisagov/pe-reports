from django import forms


class GatherStakeholderForm(forms.Form):
    cust = forms.CharField(label='Customer', max_length=500, required=True)

    custDomainAliases = forms.CharField(label='Domain Aliases', max_length=500)

    custRootDomain = forms.CharField(label='Customer Root Domain',max_length=500)

    custExecutives = forms.CharField(label='Customer Executives', max_length=500)

    def __init__(self, *args, **kwargs):
        super(GatherStakeholderForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'

class WeeklyStatusesForm(forms.Form):

    key_accomplishments = forms.CharField(label='Key accomplishments', widget=forms.Textarea(attrs={"rows": "2"}))

    ongoing_task = forms.CharField(label='Ongoing Tasks', widget=forms.Textarea(attrs={"rows": "2"}))


    upcoming_task = forms.CharField(label='Upcoming Tasks', widget=forms.Textarea(attrs={"rows": "2"}))

    obstacles = forms.CharField(label='Obstacles or Active Blockers', widget=forms.Textarea(attrs={"rows": "2"}))

    non_standard_meeting = forms.CharField(label='Non-standard meetings', widget=forms.Textarea(attrs={"rows": "2"}))

    deliverables = forms.CharField(label='Deliverables', widget=forms.Textarea(attrs={"rows": "2"}))

    pto_time = forms.CharField(label='Upcoming PTO', widget=forms.Textarea(attrs={"rows": "2"}))

    def __init__(self, *args, **kwargs):
        super(WeeklyStatusesForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'


