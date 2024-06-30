
from django.urls import path
from .views import openAccountNumber
urlpatterns = [
    path('open_account/', openAccountNumber,name='open_account'),
]
