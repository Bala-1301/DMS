import random
import requests
import json

from .models import *

API_KEY = 'a414aed8-bc72-11ea-9fa5-0200cd936042' # Get ur key from 2factor.in

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
