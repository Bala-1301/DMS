from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, serializers, permissions
from django_encrypted_filefield.views import FetchView
from rest_framework.parsers import MultiPartParser, FileUploadParser
from rest_framework.permissions import IsAuthenticated
from knox.auth import TokenAuthentication

from Users.models import *
from Users.serializers import *
from Users.otp import *
from Users.permission import has_permission

class RecordUploadRequestView(APIView):
	authentication_classes = (TokenAuthentication,)  # Authentication using Knox
	permission_classes = (IsAuthenticated,)
	
	def post(self, request, format='json'):

		if(request.user.user_type != 'Doctor'):
			msg = {
				'detail' : "Only doctors can send upload requests."
			}
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)
		
		
		if('patient_phone' not in request.data):
			msg = {
				'detail' : 'Patient phone number has to be sent with a key \'patient_phone\''
			}
			return Response(msg, status=status.HTTP_417_EXPECTATION_FAILED)

		
		doctor = Doctor.objects.get(doctor=request.user)

		patient_phone = request.data['patient_phone']
		userSet = User.objects.filter(phone=patient_phone)

		if(userSet.exists()):
			user_patient = userSet.first()
			msg = sendOTP(patient_phone)
			if(msg['ok']):
				patient = Patient.objects.get(patient=user_patient)
				otpAccount = PhoneOTP.objects.get(phone=patient_phone)
				otpAccount.doctor_id = doctor
				otpAccount.patient_id = patient
				otpAccount.save()
				return Response(msg, status=status.HTTP_200_OK)
			else:
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)
			
		else:
			msg = {
				'detail' : 'Patient with the given phone does not exist.'
			}
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)
		

class OTPVerificationView(APIView):  # view for uploading patient records 
	authentication_classes = (TokenAuthentication,)  # Authentication using Knox
	permission_classes = (IsAuthenticated,)
	
	def post(self, request, format='json'):
		if(request.user.user_type != "Doctor"):  # checks if the request is from a doctor
			msg = {
				'detail' : 'Only doctors can upload records.'
			}
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)
		
		if('patient_phone' not in request.data and 'OTP' not in request.data):
			msg = {
				'detail' : 'Insufficient data.'
			}
			return Response(msg, status=status.HTTP_417_EXPECTATION_FAILED)

		patient_phone = request.data['patient_phone']
		otp = request.data['OTP']

		userSet = User.objects.filter(phone=patient_phone)

		if(not userSet.exists()):
			msg = {
				'detail' : 'Invalid patient phone.'
			}
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)
		
		user_patient = userSet.first()
		patientSet = Patient.objects.filter(patient=user_patient)
		
		if not patientSet.exists():
			msg = {
				'detail' : 'The given patient id does not belong to a patient.'
			}
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)
		
		patient = patientSet.first()
		
		doctor = Doctor.objects.get(doctor=request.user)
		
		otpAccountSet = PhoneOTP.objects.filter(doctor_id=doctor, patient_id=patient)

		if otpAccountSet.exists():
			otpAccount = otpAccountSet.first()
			if(otp == otpAccount.otp):
				otpAccount.upload_verified = True
				otpAccount.save()
				msg = {
					'detail' : 'The Doctor can access and upload records for the patient for the next two hours.'
				}
				return Response(msg, status=status.HTTP_200_OK)
			else:
				msg = {
					'detail' : 'Invalid OTP.'
				}
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)
		else:
			msg = {
				'detail' : 'The doctor and patient doesn\'t share an OTP account.'
			}				
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)


class UploadRecordView(APIView):
	authentication_classes = (TokenAuthentication,)  # Authentication using Knox
	permission_classes = (IsAuthenticated,)
	parser_classes = (FileUploadParser,) #parses the native files that is uploaded

	def put(self, request, filename, format='json', *args, **kwargs):
		if(request.user.user_type != "Doctor"):  # checks if the request is from a doctor
			msg = {
				'detail' : 'Only doctors can upload records.'
			}
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)
		if('file' not in request.data):
			msg = {
				'detail' : 'Insufficient data.'
			}
			return Response(msg, status=status.HTTP_417_EXPECTATION_FAILED)
		
		patient_phone = kwargs['patient_phone']

		msg = has_permission(request, patient_phone)

		if msg['ok']:
			patient = msg['patient']	
			doctor = Doctor.objects.get(doctor=request.user)

			file = request.data['file']

			record = PatientRecord.objects.create(   
				patient_id=patient,
				doctor_id=doctor,
				record=file,
				record_name=filename
			)
				
			record.save()
			msg = {
				'detail' : 'Record added successfully!'
			}
			return Response(msg, status=status.HTTP_200_OK)

		else:
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)
				
			

class GetPatientRecordView(APIView):
	authentication_classes = (TokenAuthentication,)  # Authentication using Knox
	permission_classes = (IsAuthenticated,)
	
	def get(self, request, *args, **kwargs):

		if(request.user.user_type == 'Patient'):
			patient = Patient.objects.get(patient=request.user)
			records = PatientRecord.objects.filter(patient_id=patient)
			try:
				serializer = PatientRecordSerializer(data=records, many=True)
				serializer.is_valid()
				return Response(serializer.data, status=status.HTTP_200_OK)
			except:
				msg = {
					'detail' : 'Some error occurred. Please Try again.'
				}
				return Response(msg, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
		
		else:
			
			patient_phone = kwargs.get("patient_phone")

			msg = has_permission(request, patient_phone)
			
			if(msg['ok']):
				patient = msg['patient']

				records = PatientRecord.objects.filter(patient_id=patient)
				serializer = PatientRecordSerializer(records, many=True)
				return Response(serializer.data, status=status.HTTP_200_OK)
				
			else:
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)


class CustomPermission(permissions.BasePermission):

	def has_permission(self, request, view):
		print(request.path)
		if 'Authorization' in request.headers:
			knoxAuth = TokenAuthentication()
			user, auth_token = knoxAuth.authenticate(request)
			if user:
				patient_id = request.path.split("/")[-2].split("_")[1]
				if user.user_type == 'Patient':
					if(user.id == int(patient_id)):
						return True
					else:
						return False
				else:
					doctor = Doctor.objects.get(doctor=user)
					user_patient = User.objects.get(id=int(patient_id))
					patient = Patient.objects.get(patient=user_patient)
					otpAccountSet = PhoneOTP.objects.filter(patient_id=patient, doctor_id=doctor)
					if otpAccountSet.exists():
						otpAccount = otpAccountSet.first()
						if otpAccount.has_rights():
							return True
						else:
							return False
					else:
							return False
			else:
				return False

class PermissionView(APIView):
	authentication_classes = (TokenAuthentication,)
	permission_classes = (IsAuthenticated,)
	permission_classes = [CustomPermission]
	
	
class MyFetchView(PermissionView, FetchView): # view for decrypting the file 
	pass

