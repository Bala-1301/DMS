from django.urls import path, re_path
from knox.views import LogoutView
from .views import accountViews, recordViews, detailViews
from django_encrypted_filefield.constants import FETCH_URL_NAME



urlpatterns = [
	path('verify-user', accountViews.UserAccountCreateRequestView.as_view(), name='verify-user'),
	path('create-user', accountViews.UserAccountCreateView.as_view(), name='create-user'),
	path('login', accountViews.LoginView.as_view(), name='login-user'),
	path('request-access', recordViews.RecordUploadRequestView.as_view(), name='request-access'),
	path('verify-access-otp', recordViews.OTPVerificationView.as_view(), name='verify-access-otp'),
	re_path(r'^upload-record/(?P<patient_phone>\d{10})/(?P<filename>.+)', recordViews.UploadRecordView.as_view(), name='upload-record'),
	re_path(r'^get-record/(?P<patient_phone>\d{10})', recordViews.GetPatientRecordView.as_view(), name='get-record-doctor'),
	path('get-record', recordViews.GetPatientRecordView.as_view(), name='get-record-patient'),
	path('get-history', detailViews.GetTreatmentHistoryView.as_view(), name='get-history'),
	path('patient-details', detailViews.PatientDetailsView.as_view(), name='patient-details'),
	re_path(r'^patient-details/(?P<patient_phone>\d{10})', detailViews.PatientDetailsView.as_view(), name='patient-details'),
	path('logout', LogoutView.as_view(), name="logout-user"),
	re_path(r'^fetch-record/(?P<path>.+)', recordViews.MyFetchView.as_view(), name=FETCH_URL_NAME)
]