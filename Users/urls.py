from django.urls import path, re_path
from knox.views import LogoutView
from . import views
from django_encrypted_filefield.constants import FETCH_URL_NAME



urlpatterns = [
	path('verify-user', views.UserAccountCreateRequestView.as_view(), name='verify-user'),
	path('create-user', views.UserAccountCreateView.as_view(), name='create-user'),
	path('login', views.LoginView.as_view(), name='login-user'),
	path('request-access', views.RecordUploadRequestView.as_view(), name='request-access'),
	path('verify-access-otp', views.OTPVerificationView.as_view(), name='verify-access-otp'),
	re_path(r'^upload-record/(?P<patient_phone>\d{10})/(?P<filename>.+)', views.UploadRecordView.as_view(), name='upload-record'),
	re_path(r'^get-record/(?P<patient_phone>\d{10})', views.GetPatientRecordView.as_view(), name='get-record'),
	path('get-history', views.GetTreatmentHistoryView.as_view(), name='get-history'),
	path('logout', LogoutView.as_view(), name="logout-user"),
	re_path(r'^fetch-record/(?P<path>.+)', views.MyFetchView.as_view(), name=FETCH_URL_NAME)
]