from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [path('', views.index, name='index'), path('check/', views.check, name='check'), path('documents/check/', views.inspect_upload, name='inspect_document'), path('audit/', views.audit, name='audit'), path('health/', views.health, name='health'), path('admin/', admin.site.urls)]
