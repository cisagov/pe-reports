from django.urls import path
from . import views
from django.contrib.auth.decorators import login_required
from .views import StatusForm, FetchWeeklyStatusesView, WeeklyStatusesFormOnlyView

urlpatterns = [

    path('', views.home, name='home'),
    path('index/', views.index, name='index'),
    path('create_word_doc/', views.create_word_document,
         name='create_word_doc'),
    path('stakeholder/', views.stakeholder, name='stakeholder'),
    path('weekly_status/', login_required(StatusForm.as_view()),
         name='weekly_status'),
    path('fetch_weekly_statuses/',
         FetchWeeklyStatusesView.as_view(),
         name='fetch_weekly_statuses'),
    path('weekly-status-form-only/', WeeklyStatusesFormOnlyView.as_view(),
         name='weekly-status-form-only'),

]
