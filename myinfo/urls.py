from django.urls import path
from myinfo.views import myinfo_login, myinfo_callback

urlpatterns = [
    path('login/', myinfo_login, name='myinfo_login'),
    path('callback/', myinfo_callback, name='myinfo_callback'),
]
