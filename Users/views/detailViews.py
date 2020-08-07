from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, serializers, permissions
from rest_framework.permissions import IsAuthenticated
from knox.auth import TokenAuthentication


from Users.models import *
from Users.serializers import *
from Users.permission import has_permission

class PatientDetailsView(APIView):
	authentication_classes = (TokenAuthentication,)  # Authentication using Knox
	permission_classes = (IsAuthenticated,)

	def get(self, request, format='json', *args, **kwargs):

		if(request.user.user_type == 'Doctor'):
			if 'patient_phone' not in kwargs:
				return Response(status=status.HTTP_404_NOT_FOUND)

			patient_phone = kwargs['patient_phone']
			msg = has_permission(request, patient_phone)
			if(not msg['ok']):
				return Response(msg, status=status.HTTP_400_BAD_REQUEST)
			else:
				patient = msg['patient']

		else:
			patient = Patient.objects.get(patient=request.user)
	
		serializer = PatientSerializer(patient)
		return Response(serializer.data, status=status.HTTP_200_OK)
	

	def put(self, request, format='json'):
		
		if request.user.user_type == 'Patient':
			msg = {
				'detail' : 'Only doctors can enter or change patient medical details.'
			}
			return Response(msg, status=status.HTTP_400_BAD_REQUEST)

		
		patient_phone = request.data['patient_phone']

		msg = has_permission(request, patient_phone)

		if(msg['ok']):
			patient = msg['patient']
			
			serializer = PatientSerializer(patient, data=request.data)

			if(serializer.is_valid()):
				user = serializer.save()
				if user:
					return Response(serializer.data, status=status.HTTP_200_OK)
			msg = {
				'detail' : 'Invalid details'
			}
			return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

		else:
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
