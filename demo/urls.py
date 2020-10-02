from django.conf.urls import url
from django.contrib.auth import views as auth_views
from . import views




urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^signup/$', views.signup, name='signup'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',views.activate, name='activate'),
    url(r'^signin/$',views.signin,name='signin'),
    url(r'^signin/signin$',views.index,name='home'),
    url(r'^signin/logout$',views.logout,name='logout'),
    url(r'phone/', views.getPhoneNumberRegistered, name="OTP Gen"),

]