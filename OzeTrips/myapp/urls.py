from django.urls import path
from .views import register_user, verify_otp, login_user, logout_user, retrieve_or_update_user,update_password

app_name = 'myapp'

urlpatterns = [
    path('register/', register_user, name='register_user'),
    path('verify-otp/', verify_otp, name='verify_otp'),
    path('login/', login_user, name='login_user'),
    path('logout/', logout_user, name='logout_user'),
    path('userdata/', retrieve_or_update_user, name='retrieve_user_by_name'),  # Fix the import here
    path('update-password/', update_password, name='update_password'),
]
