from django.urls import path
from . import views
from django.contrib.auth.decorators import login_required
from .views import StatusForm

urlpatterns = [

    path('', views.home, name='home'),
    path('index/', views.index, name='index'),
    path('stakeholder/', views.stakeholder, name='stakeholder'),
    path('weekly_status/', login_required(StatusForm.as_view()),
         name='weekly_status'),

]
