from django.conf.urls import patterns, url


from .views import lm

urlpatterns = patterns(
    '',
    url(r'^$', lm),
   # url(r'^api/miserables', miserables, name='miserables'),
)