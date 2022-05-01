"""PulseMaster URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
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
from django.urls import path, include

app_name = 'Outer_updates'
from .views import BindUpdateView, BindInitView, UpdateBaseZoneFile, RefreshBaseZoneFile, RefreshView
urlpatterns = [
    path('refresh/', RefreshView.as_view(), name='refresh'),
    path('refresh-base-zone/', RefreshBaseZoneFile.as_view(), name='refresh_base_zone'),
    path('update-base-zone/', UpdateBaseZoneFile.as_view(), name='update_base_zone'),
    path('update-bind/', BindUpdateView.as_view(), name='bind_update_api'),
    path('init-bind/', BindInitView.as_view(), name='bind_init_api'),
]
