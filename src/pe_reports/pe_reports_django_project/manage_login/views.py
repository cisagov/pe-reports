
# Third party imports
from django.shortcuts import render, redirect
from .forms import NewUserForm
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, logout
from django.contrib import messages
from django.http import  HttpResponseRedirect


def register_request(request):
    if request.method == "POST":
        form = NewUserForm(request.POST)
        if form.is_valid():
            personRegistered = form.cleaned_data.get('username')
            user = form.save()
            login(request, user)
            messages.success(request, f"Registration successful - {personRegistered}.")
            return redirect("/logout")
        messages.error(request,
                       "Unsuccessful registration. Invalid information.")
    form = NewUserForm()
    return render(request=request, template_name="register/register.html",
                  context={"register_form": form})


def login_request(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.info(request, f"You are now logged in as {username}.")
                return redirect("/")
            else:
                messages.error(request, "Invalid username or password.")
        else:
            messages.error(request, "Invalid username or password.")
    form = AuthenticationForm()
    return render(request=request, template_name="register/login.html",
                  context={"login_form": form})


def logout_view(request):
    logout(request)
    return redirect("/")
