from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.base_user import BaseUserManager

class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, phone_number, password=None, role=None, first_name='', last_name='', email='', **extra_fields):
        try:
            if not phone_number:
                raise ValueError('Phone Number is required')
            if not email:
                raise ValueError('Email is required')
            email = self.normalize_email(email)
            user = self.model(phone_number=phone_number, role=role, first_name=first_name, last_name=last_name, email=email, **extra_fields)
            user.set_password(password)
            user.save(using=self._db)
            return user
        except Exception as e:
            print(e)

    def create_superuser(self, phone_number, password=None, role=None, first_name='', last_name='', email='', **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(phone_number, password, role, first_name, last_name, email, **extra_fields)

class User(AbstractUser):
    phone_number = models.CharField(max_length=10, unique=True)
    role = models.CharField(max_length=10)
    email = models.EmailField(unique=True)
    isAccount=models.BooleanField(default=False,null=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['email', 'role', 'first_name', 'last_name']

    objects = UserManager()

class OTP(models.Model):
    session_id = models.CharField(max_length=100, null=True)
    otp = models.CharField(max_length=10)
    counter = models.IntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)