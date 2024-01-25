"""manage_login module forms.py."""
# Third-Party Libraries
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

# Create your forms here.


class NewUserForm(UserCreationForm):
    """NewUserForm class."""

    email = forms.EmailField(required=True)

    class Meta:
        """NewUserForm meta class."""

        model = User
        fields = ("username", "email", "password1", "password2")

    def save(self, commit=True):
        """Save function."""
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user
