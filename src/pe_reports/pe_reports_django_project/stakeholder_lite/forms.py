# Third-Party Libraries
from django import forms


class GatherStakeholderLiteForm(forms.Form):
    orgCount = forms.CharField(
        label="How many organizations", max_length=500, required=True
    )

    def __init__(self, *args, **kwargs):
        super(GatherStakeholderLiteForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"
