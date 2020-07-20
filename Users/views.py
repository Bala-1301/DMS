from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, serializers, permissions
from django.contrib.auth import login
from django.contrib.auth.password_validation import validate_password, ValidationError
from django.views.decorators.csrf import csrf_exempt
from knox.views import LoginView as KnoxLoginView
import random
import requests
import json

from .models import *
from .serializers import *

API_KEY = '' # Get ur key from 2factor.in

class UserAccountCreateRequestView(APIView):
	
	# Get request for getting the phone number of user and sending OTP (requires a phone number)
	def post(self, request, format='json'):
		
		if 'phone' in request.data:
			phone = request.data['phone']
	
			if User.objects.filter(phone=phone).exists(): # check if the number already exists
					msg = {
						'status' : status.HTTP_400_BAD_REQUEST,
						'detail' : 'User with the given phone number already exists.'
					}
					return Response(msg)
	
			else: # if user phone does not exists send OTP
				msg = sendOTP(request.data)
				return Response(msg)
	
		else:
			msg = {
				'status': status.HTTP_417_EXPECTATION_FAILED,
				'detail' : 'Need a phone number with key as \'phone\''
			}
			return Response(msg)
	
	
class UserAccountCreateView(APIView):
	
	# post request for creating the user if the otp verification is successful (requires a phone number and password with optional name and email)
	def post(self, request, format='json'):
		keys = ('phone', 'password', 'gender', 'user_type', 'OTP', 'name')

		if all(key in request.data for key in keys):
			
			if(request.data['user_type'] == 'Doctor' and 'licence_no' not in request.data):
				msg = {
					'status': status.HTTP_417_EXPECTATION_FAILED,
					'detail' : 'Doctors must have an licence number'
				} 
				return Response(msg)

			msg = verifyOTP(request.data)
			if( msg['status'] != 200):
				return Response(msg)

			phone = request.data['phone']
			password = request.data['password']
			userSet = PhoneOTP.objects.filter(phone=phone)

			if userSet.exists(): # check if any OTP has been sent to the user
				user = userSet.first()
	
				if user.verified: # if verified create user account
					
					try:
						validate_password(password, user=request.data) # validating password
					except ValidationError as err:
						return Response(err, status=status.HTTP_406_NOT_ACCEPTABLE)
	
					user.delete()  # deleting the user entry in PhoneOTP model
					serializer = UserCreateSerializer(data=request.data) 
					if serializer.is_valid():
						user = serializer.save()
						if user:
							msg = {
								'status' : status.HTTP_200_OK,
								'detail'  : "Account created successfully"
							}
							return Response(msg)
						else: 
							msg = {
								'status' : status.HTTP_400_BAD_REQUEST,
								'detail' : 'Internal server error'
							}
							return Response(msg)
					else: 
						msg = {
							'status' : status.HTTP_406_NOT_ACCEPTABLE,
							'detail' : 'Invalid credentials'
						}	
						return Response(msg)
				else:
					msg = {
						'status' : status.HTTP_400_BAD_REQUEST,
						'detail': 'The user has not been verified yet.'
					}
					return Response(msg)
			
			else:
				msg = {
					'status' : status.HTTP_400_BAD_REQUEST,
					'detail' : 'The user is not verified and not sent any OTP.'
				}
				return Response(msg)
		
		else:
			msg = {
				'status': status.HTTP_417_EXPECTATION_FAILED,
				'detail' : 'Insufficient data'
			}
			return Response(msg)
	
	def put(self, request, format='json'):
		keys = ('public_key', 'private_key', 'phone')
		if all(key in request.data for key in keys):

			user_set = User.objects.filter(phone=request.data['phone'])
			
			if user_set.exists():
				user = user_set.first()
				user.public_key = request.data['public_key']
				user.encrypted_private_key = request.data['private_key']
				user.ready = True
				user.save()
				if (user.user_type == 'Doctor'):
					doctor = Doctor.objects.create(
						doctor = user
					)
					doctor.save()
				else:
					patient = Patient.objects.create(
						patient = user
					)
					patient.save()
				msg = {
					'status' : status.HTTP_202_ACCEPTED,
					'detail' : 'Keys set successfully'
				}
				return Response(msg)
			else:
				msg = {
					'status' : status.HTTP_400_BAD_REQUEST,
					'detail' : 'User with the given phone does not exists'
				}
				return Response(msg)
		else:
			msg = {
				'status' : status.HTTP_406_NOT_ACCEPTABLE,
				'detail' : 'Insufficient data'
			}
			return Response(msg)

# function to send OTP
def sendOTP(data):
		phone = data['phone']
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
					'status' : status.HTTP_429_TOO_MANY_REQUESTS,
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
			'status' : status.HTTP_200_OK,
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
						'status' : status.HTTP_200_OK,
						'detail' : 'Accepted'
				}
				return msg
			else:
				msg = {
					'status': status.HTTP_400_BAD_REQUEST,
					'detail' : 'OTP does not match.'
				}
				return msg
		else:
			msg = {
				'status': status.HTTP_400_BAD_REQUEST,
				'detail' : 'Invalid Request'
			}
			return msg


class LoginView(KnoxLoginView):
	permission_classes = (permissions.AllowAny, )
	
	def post(self, request, format='json'):
		
		try:
			serializer = LoginSerializer(data=request.data)
			serializer.is_valid(raise_exception=True)
			user = serializer.validated_data['user']
			login(request, user)
			return super().post(request, format='json')
		except ValidationError as err:
			return Response(err, status=status.HTTP_400_BAD_REQUEST)