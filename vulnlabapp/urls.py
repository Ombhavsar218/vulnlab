from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
]
