from django.conf.urls import patterns, url


from .views import gmaps
from .views import ajax
from .views import *


urlpatterns = patterns(
    '',
    url(r'^$', gmaps),
    url(r'^api/postes', ajax, name='ajax'),
    url(r'^api/gmapse', gmapse),
    url(r'^api1/postes', ajax1, name='ajax1'),
    url(r'^api2/postes', ajax2, name='ajax2')
    #url(r'^/detail', ShowZoneDetail, name='detail'),
)