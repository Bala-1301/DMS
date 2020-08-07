from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, serializers, permissions
from django.contrib.auth import login
from django.contrib.auth.password_validation import validate_password, ValidationError
from knox.views import LoginView as KnoxLoginView
from django.utils import timezone

from datetime import datetime, timedelta

from Users.models import *
from Users.serializers import *
from Users.otp import * 

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

		if not all(key in request.data for key in keys):
			msg = {
				'detail' : 'Insufficient data'
			}
			return Response(msg, status=status.HTTP_417_EXPECTATION_FAILED)
	
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
					
				msg = {
					'detail' : 'Invalid data.'
				}	
				return Response(msg, status=status.HTTP_406_NOT_ACCEPTABLE)
			
		msg = {
			'detail' : 'OTP verification is not yet done.'
		}
		return Response(msg, status=status.HTTP_400_BAD_REQUEST)
	
		
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



def clearOTP():
	otpAccountSet = PhoneOTP.objects.all()
	for otpAccount in otpAccountSet:
		hours = timedelta(hours=2)
		current_time = timezone.now()
		print(current_time)
		if otpAccount.created_at+hours <= current_time:
			print("Deleting...")
			otpAccount.delete()

