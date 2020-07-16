from django.db import models
from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _

class UserManager(BaseUserManager):
	
	def create_user(self, phone=None, password=None, email=None, user_type=None, gender=None, is_active=True, is_admin=False):
		if not phone:
			raise ValueError("User must have a phone number")
		if not password:
			raise ValueError("User must have a password")

		user = self.model(
			phone=phone
		)
		user.set_password(password)
		user.email = email
		user.user_type = user_type
		user.gender = gender
		user.is_active = is_active
		user.is_admin = is_admin
		user.save(using=self._db)
		return user

	def create_superuser(self, phone, email,gender, user_type, password=None):
		user = self.create_user(
			phone=phone,
			password=password,
			email=email,
			gender=gender,
			user_type=user_type
		)
		user.is_admin = True
		user.save(using=self._db)
		return user
		
class User(AbstractBaseUser):
	phone_regex = RegexValidator(regex= '^[6789]{1}\d{9}', message="Phone number must be a 10 digit number")
	phone = models.CharField(validators = [phone_regex], max_length=10, unique=True)
	name = models.CharField(max_length=64, null=True, blank=True)
	email = models.EmailField(verbose_name="email address", unique=True, null=True, blank=True)
	class UserTypeChoices(models.TextChoices):
		Doctor = 'Dr', _('DOCTOR')
		Patient = 'Pt', _('PATIENT')
		Admin = 'Ad', _('Admin')
		
	user_type = models.CharField(max_length=2, choices=UserTypeChoices.choices, default=None)
	
	class GenderChoices(models.TextChoices):
		Male = 'M', _('MALE')
		Female = 'F', _('FEMALE')
		Other = 'O', _('OTHER')
	
	gender = models.CharField(max_length=1, choices=GenderChoices.choices, default=None)
	
	is_active = models.BooleanField(default=True)
	is_admin = models.BooleanField(default=False)
	
	USERNAME_FIELD = 'phone'
	REQUIRED_FIELDS = ['email', 'gender', 'user_type']

	objects = UserManager()

	def __str__(self):
		return self.phone

	def get_full_name(self):
		if self.name:
			return self.name
		else:
			return self.phone

	def has_perm(self, perm, obj=None):
		return True

	def has_module_perms(self, app_label):
		return True

	@property
	def is_staff(self):
		return self.is_admin
	

class Doctor(models.Model):
	doctor = models.OneToOneField(User, on_delete=models.CASCADE) 
	licence_no = models.CharField(max_length=20)
	public_key = models.CharField(max_length=300, blank=True, null=True)
	encrypted_private_key = models.CharField(max_length=300, blank=True, null=True)

	
class Patient(models.Model):
	patient = models.OneToOneField(User, on_delete=models.CASCADE)
	
	public_key = models.CharField(max_length=300, blank=True, null=True)
	encrypted_private_key = models.CharField(max_length=300, blank=True, null=True)

	


