from unicodedata import name
from django.urls import path

from . import views


urlpatterns = [
    path('', views.indexRedirect, name = 'indexRedirect'),
    path('index/', views.index, name = 'index'),
    path('package_upload/', views.package_upload, name = 'package_upload'),
    path('protocol_resolution/', views.protocol_resolution, name = 'protocol_resolution'),
    path('protocol_resolution_p/<int:pIndex>', views.protocol_resolution_p, name = 'protocol_resolution_p'),
    path('chart/', views.chart, name = 'chart'),
    path('intrusion_detection/', views.intrusion_detection, name = 'intrusion_detection'),
    path('real_time_network/', views.real_time_network, name = 'real_time_network'),
]