from .models import *

def has_permission(request, patient_phone):

	userSet = User.objects.filter(phone=patient_phone)
	if not userSet.exists():
		msg = {
			'ok' : False,
			'detail' : 'A patient with the given phone doesn\'t exist.'
		}
		return msg

	user = userSet.first()
	patientSet = Patient.objects.filter(patient=user)
	
	if not patientSet.exists():
		msg = {
			'ok' : False,
			'detail' : 'The given phone does not belong to a patient.'
		}
		return msg
	
	patient = patientSet.first()
	
	doctor = Doctor.objects.get(doctor=request.user)

	otpAccountSet = PhoneOTP.objects.filter(doctor_id=doctor, patient_id=patient)
	if(otpAccountSet.exists()):
		otpAccount = otpAccountSet.first()
		if (otpAccount.has_rights()):
			msg = {
				'ok' : True,
				'patient' : patient
			}
			return msg
		else:
			msg = {
				'ok' : False,
				'detail' : 'OTP verification is not done.'
			}
			return msg
	else:
		msg = {
			'ok' : False,
			'detail' : 'The Doctor and the Patient doesn\'t share an OTP Account.'
		}
		return msg
