from django.urls import path
from .views import *

urlpatterns = [
    path('', home, name="home"),
    path('signup', signup, name="signup"),
    path('login', login_up, name="login"),
    path('resend_otp/<str:gmail>', resend_otp, name="resend_otp"),
    path('verify/<str:data>', verify, name="verify"),
    path('logout', logout_up, name="logout"),
    path('add_tractor', add_tractor, name="add_one"),
    path('tractors', the_tractors, name="all_tracks"),
    path('tractors/delete/<str:sluggu>', delete_record, name="delete_record"),
    path('tractors/<str:tracker>', single_tracker, name="single"),
    path('getting_all_of_them', get_all_tractors, name="all_tracs"),
    path('profile', profile, name="profile")
]
