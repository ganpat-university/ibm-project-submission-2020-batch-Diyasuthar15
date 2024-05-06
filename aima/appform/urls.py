from django.urls import path
from .views import *

urlpatterns = [
    path('', redirectURL, name='index'),
    path('home/', home, name='home'),
    path('store-apk/', store_apk, name='store-apk'),
    path('analyze-apk/', analyzeApk, name='analyze-apk'),
    path('wait-page/', waitPage, name='wait-page'),
    path('results/', showResult, name='show-result'),
    path('permission/', populatePermissionCount, name='permission-count'),
]