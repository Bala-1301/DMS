from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, serializers, permissions
from django.contrib.auth import login
from django.contrib.auth.password_validation import validate_password, ValidationError
from django.views.decorators.csrf import csrf_exempt
from knox.views import LoginView as KnoxLoginView
from django_encrypted_filefield.views import FetchView
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from knox.auth import TokenAuthentication
from django.utils import timezone

import random
import requests
import json
import sys
import schedule
from datetime import datetime, timedelta
import time
import threading

from .models import *
from .serializers import *

API_KEY = 'a414aed8-bc72-11ea-9fa5-0200cd936042' # Get ur key from 2factor.in

class UserAccountCreateRequestView(APIView):
	
	# Get request for getting the phone number of user and sending OTP (requires a phone number)
	def post(self, request, format='json'):
		
		if 'phone' not in request.data and 'user_type' not in request.data:
			msg = {
				'detail' : 'Insufficient credentials'
			}
			return Response(msg, status=status.HTTP_417_EXPECTATION_FAILED)
		
		if request.data['user_type'] == 'Doctor':
			if 'licence_no' not in request.data:
				msg = {
				'detail' : 'Doctors must have an licence number'
				}
				return Response(msg, status=status.HTTP_417_EXPECTATION_FAILED)
			else:
				if(User.objects.filter(licence_no=request.data['licence_no']).exists()):
					msg = {
						'detail' : 'Doctor with the given licence number already exists.'
					}
					return Response(msg, status=status.HTTP_400_BAD_REQUEST)
	
		if 'email' in request.data:
			if User.objects.filter(email=request.data['email']).exists():
				msg = {
					'detail' : 'User with the given email already exists.'
				}
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)

			
		if User.objects.filter(phone=request.data['phone']).exists(): # check if the number already exists
				msg = {
					'detail' : 'User with the given phone number already exists.'
				}
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)
	
			 # if user does not exists send OTP
		msg = sendOTP(request.data['phone'])
		if(msg['ok']):
			return Response(msg, status=status.HTTP_200_OK)
		else:
			return Response(msg, status=status.HTTP_429_TOO_MANY_REQUESTS)

	
class UserAccountCreateView(APIView):
	
	# post request for creating the user if the otp verification is successful (requires a phone number and password with optional name and email)
	def post(self, request, format='json'):
		keys = ('phone', 'password', 'gender', 'user_type', 'OTP', 'name')

		if all(key in request.data for key in keys):
			
			if(request.data['user_type'] == 'Doctor'):
				if('licence_no' not in request.data):
					msg = {
						'detail' : 'Doctors must have an licence number'
					} 
					return Response(msg, status=status.HTTP_417_EXPECTATION_FAILED)
				if(User.objects.filter(licence_no=request.data['licence_no']).exists()):
					msg = {
						'detail' : 'A Doctor with the given licence number already exists.'
					}
					return Response(msg, status=status.HTTP_400_BAD_REQUEST)

			if('email' in request.data):
				if(User.objects.filter(email=request.data['email']).exists()):
					msg = {
						'detail' : 'User with the given email already exists.'
					}
					return Response(msg, status=status.HTTP_400_BAD_REQUEST)


			msg = verifyOTP(request.data)
			if(not msg['ok']):
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)

			phone = request.data['phone']
			password = request.data['password']
			userSet = PhoneOTP.objects.filter(phone=phone)

			if userSet.exists(): # check if any OTP has been sent to the user
				user = userSet.first()
	
				if user.is_verified(): # if verified create user account
					try:
						validate_password(password, user=request.data) # validating password
					except ValidationError as err:
						return Response(err, status=status.HTTP_406_NOT_ACCEPTABLE)
	
					serializer = UserCreateSerializer(data=request.data) 
					if serializer.is_valid():
						created_user = serializer.save()
						if created_user:
							user.delete()   # deleting the entry in PhoneOTP model once user is created
							if (created_user.user_type == 'Doctor'):  #if user is doctor add to doctor model
								doctor = Doctor.objects.create(
									doctor = created_user
								)
								doctor.save()
							else: # if patient add to patient model
								patient = Patient.objects.create(
									patient = created_user
								)
								patient.save()
							return Response(serializer.data, status=status.HTTP_200_OK)
						else: 
							msg = {
								'detail' : 'Details are not valid'
							}
							return Response(msg, status=status.HTTP_400_BAD_REQUEST)
					else: 
						msg = {
							'detail' : 'Invalid data.'
						}	
						return Response(msg, status=status.HTTP_406_NOT_ACCEPTABLE)
				else:
					msg = {
						'detail': 'The user has not been verified yet.'
					}
					return Response(msg, status=status.HTTP_400_BAD_REQUEST)
			
			else:
				msg = {
					'detail' : 'The user is not verified and not sent any OTP.'
				}
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)
		
		else:
			msg = {
				'detail' : 'Insufficient data'
			}
			return Response(msg, status=status.HTTP_417_EXPECTATION_FAILED)
	
	def put(self, request, format='json'): # put method for adding the encryption keys
		keys = ('public_key', 'private_key', 'phone')
		if all(key in request.data for key in keys):

			user_set = User.objects.filter(phone=request.data['phone'])
			
			if user_set.exists():
				user = user_set.first()
				user.public_key = request.data['public_key']
				user.encrypted_private_key = request.data['private_key']
				user.ready = True
				user.save()
				
				msg = {
					'detail' : 'Keys set successfully'
				}
				return Response(msg, status=status.HTTP_200_OK)
			else:
				msg = {
					'detail' : 'User with the given phone does not exists'
				}
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)
		else:
			msg = {
				'detail' : 'Insufficient credentials'
			}
			return Response(msg, status=status.HTTP_406_NOT_ACCEPTABE)

# function to send OTP
def sendOTP(phone):
		# OTP = random.randint(999, 9999) #comment this while testing
		OTP = '1234' # uncomment for testing
		url = "https://2factor.in/API/V1/{0}/SMS/+91{1}/{2}".format(API_KEY, phone, OTP)
		otpAccount = PhoneOTP.objects.filter(phone=phone) 

		# check if the OTP has already been to the user
		# if sent check the OTP count if within limits 
		# if within limit send OTP again and increment the count
		# else cancel the request
		
		if otpAccount.exists():
			user = otpAccount.first()
			count = user.count
			if count >= 6:
				msg = {
					'ok' : False,
					'detail': 'Too many attempts. Try again after 24 Hours.'
				}
				return msg
			user.otp = OTP
			user.count = count + 1
			user.save()
		# if the OTP has not been send already send the otp
		else:
			user = PhoneOTP.objects.create(
				phone = phone,
				otp = OTP,
				count = 1
			)
			user.save()
		
		# response = requests.get(url) # comment for testing
		# resp = response.json()  # comment for testing
		msg = {
			'ok' : True,
			'detail' : 'OTP sent successfully.'
		}
		return msg

# function to verify OTP
def verifyOTP(data):
		phone = data['phone']
		receivedOTP = data['OTP']
		userSet = PhoneOTP.objects.filter(phone=phone)
		# check if an OTP has been sent to the user
		if userSet.exists():
			#if sent verify the OTP
			user = userSet.first()
	
			if user.otp == receivedOTP:
				user.verified = True
				user.save()
				msg = {
						'ok' : True,
						'detail' : 'Accepted'
				}
				return msg
			else:
				msg = {
					'ok': False,
					'detail' : 'OTP does not match.'
				}
				return msg
		else:
			msg = {
				'ok' : False,
				'detail' : 'Invalid Request'
			}
			return msg


class LoginView(KnoxLoginView):
	permission_classes = (permissions.AllowAny, )
	
	def post(self, request, format='json'):
		if('phone' in request.data and 'password' in request.data):
			serializer = LoginSerializer(data=request.data)
			if(serializer.is_valid()):
				user = serializer.validated_data['user']
				login(request, user)
				return super().post(request, format='json')
			else:
				return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
		else:
			msg = {
				'detail': 'Insufficient credentials'
			}
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)

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
	parser_classes = (MultiPartParser,) #parses the native files that is uploaded

	def post(self, request, format='json'):
		if(request.user.user_type != "Doctor"):  # checks if the request is from a doctor
			msg = {
				'detail' : 'Only doctors can upload records.'
			}
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)
		if('patient_phone' not in request.data or 'file' not in request.FILES):
			msg = {
				'detail' : 'Insufficient data.'
			}
			return Response(msg, status=status.HTTP_417_EXPECTATION_FAILED)
		
		patient_phone = request.data['patient_phone']
		userSet = User.objects.filter(phone=patient_phone)
		if not userSet.exists():
			msg = {
				'detail' : 'A patient with the given phone doesn\'t exist.'
			}
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)

		user = userSet.first()
		patientSet = Patient.objects.filter(patient=user)
		
		if not patientSet.exists():
			msg = {
				'detail' : 'The given phone does not belong to a patient.'
			}
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)
		
		patient = patientSet.first()
		
		doctor = Doctor.objects.get(doctor=request.user)
		print(request.data['file'])
		otpAccountSet = PhoneOTP.objects.filter(doctor_id=doctor, patient_id = patient)
		if(otpAccountSet.exists()):
			otpAccount = otpAccountSet.first()
			file = request.data['file']
			if (otpAccount.has_rights()):
				record = PatientRecord.objects.create(   
					patient_id=patient,
					doctor_id=doctor,
					record=file,
					record_name=file.name
				)
				
				record.save()
				msg = {
					'detail' : 'Record added successfully!'
				}
				return Response(msg, status=status.HTTP_200_OK)
			else:
				msg = {
					'detail' : 'OTP verification is not done.'
				}
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)
		else:
			msg = {
				'detail' : 'The Doctor and the Patient doesn\'t share an OTP Account.'
			}
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
			
			userSet = User.objects.filter(phone=patient_phone)
			if not userSet.exists():
				msg = {
					'detail' : 'A patient with the given phone doesn\'t exist.'
				}
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)

			user = userSet.first()
			patientSet = Patient.objects.filter(patient=user)
			
			if not patientSet.exists():
				msg = {
					'detail' : 'The given phone does not belong to a patient.'
				}
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)
			
			patient = patientSet.first()

			doctor = Doctor.objects.get(doctor=request.user)

			otpAccountSet = PhoneOTP.objects.filter(doctor_id=doctor, patient_id = patient)

			if(otpAccountSet.exists()):
				otpAccount = otpAccountSet.first()
				if (otpAccount.has_rights()):
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
					msg = {
						'detail' : 'OTP verification is not done.'
					}
					return Response(msg, status=status.HTTP_400_BAD_REQUEST)
			else:
				msg = {
					'detail' : 'The Doctor and the Patient doesn\'t share an OTP Account.'
				}
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)


class GetTreatmentHistoryView(APIView):
	authentication_classes = (TokenAuthentication,)  # Authentication using Knox
	permission_classes = (IsAuthenticated,)

	def get(self, request, format='json'):
		if request.user.user_type != 'Doctor':
			msg = {
				'detail' : 'Invalid request.'
			}
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)

		doctor = Doctor.objects.get(doctor=request.user)

		records = PatientRecord.objects.filter(doctor_id=doctor)
		try:
			serializer = DoctorHistorySerializer(data=records, many=True)
			serializer.is_valid()
			return Response(serializer.data, status=status.HTTP_200_OK)
		except:
			msg = {
				'detail' : 'Some error occurred. Please Try again.'
			}
			return Response(msg, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
			
	
class CustomPermission(permissions.BasePermission):

	def has_permission(self, request, view):
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


def clearOTP():
	otpAccountSet = PhoneOTP.objects.all()
	for otpAccount in otpAccountSet:
		hours = timedelta(hours=2)
		current_time = timezone.now()
		if otpAccount.created_at+hours <= current_time:
			print("Deleting...")
			otpAccount.delete()

