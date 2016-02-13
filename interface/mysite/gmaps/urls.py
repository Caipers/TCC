from django.conf.urls import patterns, url


from .views import gmaps
from .views import ajax


urlpatterns = patterns(
    '',
    url(r'^$', gmaps),
    url(r'^api/postes', ajax, name='ajax'),
    #url(r'^/detail', ShowZoneDetail, name='detail'),
)