from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name="index"),
    url(r'^index$', views.index, name="index"),
    # url(r'^add$', views.new, name="add"),
    # url(r'^new$', views.new, name="new"),
    url(r'^signin$', views.login_page, name="signin"),
    url(r'^login$', views.login, name="login"),
    url(r'^dashboard$', views.dashboard, name="dashboard"),
    url(r'^register$', views.register_page, name="register"),
    url(r'^create$', views.register, name="create"),
    url(r'^edit_users/$', views.edit_users, name="edit_users"),
    url(r'^(?P<user_id>\d+)/edit/$', views.edit, name="edit"),
    url(r'^(?P<user_id>\d+)/show/$', views.show, name="show"),
    url(r'^(?P<user_id>\d+)/update/$', views.show, name="update"),
    url(r'^(?P<user_id>\d+)/delete/$', views.delete, name="delete"),
    url(r'^(?P<user_id>\d+)/message/$', views.message, name="message"),
    url(r'^(?P<message_id>\d+)/comment/$', views.comment, name="comment"),
    url(r'^logout/$', views.logout, name="logout"),
]