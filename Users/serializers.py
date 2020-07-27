from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework import status

from .models import *
from django.contrib.auth import get_user_model

User = get_user_model()

class UserCreateSerializer(serializers.ModelSerializer):

	def create(self, validated_data):
		user = User.objects.create_user(
			phone=validated_data['phone'],
			password=validated_data['password'],
			name=validated_data['name'],
			gender=validated_data['gender'],
			user_type=validated_data['user_type'],
		)
		if(validated_data['user_type'] == 'Doctor'):
			user.licence_no = validated_data['licence_no']
		if 'email' in validated_data:
			user.email=validated_data['email']
		user.save()
		return user

	class Meta:
		model = User
		fields = ('id', 'phone', 'password', 'name', 'email', 'gender', 'user_type', 'licence_no')
		extra_kwargs = {'password' : {'write_only' : True }}

class UserSerializer(serializers.ModelSerializer):

	class Meta:
		model = User
		fields = ('id', 'phone', 'name', 'email', 'gender', 'user_type', 'licence_no')

	
class LoginSerializer(serializers.Serializer):

	phone = serializers.CharField()
	password = serializers.CharField(
		style = { 'input_type': 'password'}, trim_whitespace=False
	)

	def validate(self, data):
		phone = data.get('phone')
		password = data.get('password')

		if phone and password:
			if User.objects.filter(phone=phone).exists():
				user = authenticate(request=self.context.get('request'), phone=phone, password=password)
				if user:
					data['user'] = user
					return data
				else:
					msg = {
						'detail' : 'Invalid Password.'
					}
					raise serializers.ValidationError(msg)
			else:
				msg = {
					'detail' : 'User with the given phone number does not exist.' 
				}
				raise serializers.ValidationError(msg)
		else:
			msg = {
				'detail': 'Insufficient credentials' 
			}
			raise serializers.ValidationError(msg)


class DoctorDataSerializer(serializers.ModelSerializer):

	class Meta:
		model = User
		fields = ('id', 'name', 'phone', 'licence_no')


class DoctorSerializer(serializers.ModelSerializer):
	doctor = DoctorDataSerializer()

	class Meta:
		model = Doctor
		fields = ('id', 'doctor')

class PatientRecordSerializer(serializers.ModelSerializer):
	
	doctor_id = DoctorSerializer()
	
	class Meta:
		model = PatientRecord
		fields = ('id', 'doctor_id', 'record', 'created_at')

class PatientDataSerializer(serializers.ModelSerializer):

	class Meta:
		model = User
		fields = ('id', 'name', 'phone')


class PatientSerializer(serializers.ModelSerializer):
	doctor = PatientDataSerializer()

	class Meta:
		model = Doctor
		fields = ('id', 'doctor')


class DoctorHistorySerializer(serializers.ModelSerializer):

	patient_id = PatientSerializer

	class Meta:
		model = PatientRecord
		fields = ('id', 'patient_id', 'created_at')