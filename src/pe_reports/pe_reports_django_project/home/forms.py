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

