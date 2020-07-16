from django.urls import path
from knox.views import LogoutView
from . import views

urlpatterns = [
	path('verify-user', views.UserAccountCreateRequestView.as_view(), name='verify-user'),
	path('create-user', views.UserAccountCreateView.as_view(), name='create-user'),
	path('login', views.LoginView.as_view(), name='login-user'),
	path('logout', LogoutView.as_view(), name="logout-user")
]