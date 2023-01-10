from django.urls import path
from .views import *


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('email_verify/', VerifyEmail.as_view(), name='email_verify'),
    path('login/', LoginApiView.as_view(), name='login'),
]