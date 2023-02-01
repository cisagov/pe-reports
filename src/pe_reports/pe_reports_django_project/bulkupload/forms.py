from django import forms

class CSVUploadForm(forms.Form):
    file = forms.FileField()

    def clean(self):
        cleaned_data = super().clean()
        file = cleaned_data.get("file")
        if not file.name.endswith(".csv"):
            raise ValidationError(
                {
                    "file": _("Filetype not supported, the file must be a '.csv'"),
                }
            )
        return cleaned_data
