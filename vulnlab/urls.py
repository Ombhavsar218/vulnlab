"""
URL configuration for vulnlab project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf import settings

from django.conf.urls.static import static
from vulnlabapp import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.login_view, name='login'),
    path('admin-login/', views.admin_login_view, name='admin_login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('search/', views.search_view, name='search'),
    path('directory/', views.directory_view, name='directory'),
    path('upload/', views.upload_view, name='upload'),
    path('profile/', views.profile_view, name='profile'),
    path('logs/', views.logs_view, name='logs'),
    path('register/', views.register_view, name='register'),
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('admin-portal/', views.admin_dashboard_view, name='admin_portal'),
    path('browse/', views.browse_view, name='browse'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
