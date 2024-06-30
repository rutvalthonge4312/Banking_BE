
from django.urls import path
from .views import verify_phone,login,signup,update_password,update_mPin
urlpatterns = [
    path('verify_mobile/', verify_phone,name='verify_phone'),
    path('login/', login,name='login'),
    path('signup/', signup,name='signup'),
    path('update_password/', update_password,name='update_password'),
    path('update_mpin/', update_mPin,name='update_mpin'),
]
