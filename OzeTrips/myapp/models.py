from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.contrib.auth.hashers import make_password
import random
import requests

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        if password is None:
            raise ValueError('Superuser must have a password')
        return self.create_user(email, password, **extra_fields)
class User(AbstractBaseUser, PermissionsMixin):
    user_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    birthdate = models.DateField(blank=True, null=True)
    email = models.EmailField(max_length=255, unique=True)
    phone_number = models.CharField(max_length=15)  # Phone number is now editable
    GENDER_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other')
    ]
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, blank=True)
    password = models.CharField(max_length=255)
    MARITAL_STATUS_CHOICES = [
        ('Single', 'Single'),
        ('Married', 'Married'),
        ('Divorced', 'Divorced'),
        ('Widowed', 'Widowed'),
        ('Separated', 'Separated')
    ]
    marital_status = models.CharField(max_length=10, choices=MARITAL_STATUS_CHOICES, blank=True)
    address = models.CharField(max_length=255, blank=True)
    state = models.CharField(max_length=100, blank=True)
    pincode = models.CharField(max_length=20, blank=True)
    create_date = models.DateField(auto_now_add=True)
    create_time = models.TimeField(auto_now_add=True)
    create_location = models.CharField(max_length=255, blank=True)
    email_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    user_identifier = models.CharField(max_length=255, blank=True, editable=False)  # New field
    last_update_date = models.DateField(blank=True, null=True)
    last_update_time = models.TimeField(blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    class Meta:
        unique_together = ('name', 'create_time')

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.pk or kwargs.get('force_insert', False):  # Generate user_id if it's a new instance or force_insert is True
            self.user_id = None
            self.user_identifier = f"{self.name}_{timezone.now().strftime('%Y%m%d%H%M%S')}"
        if not self.is_password_hashed(self.password):
            self.password = make_password(self.password)
        if not self.create_location:
            self.create_location = self.get_user_location()
        self.last_update_date = timezone.now().date()
        self.last_update_time = timezone.now().time()
        super().save(*args, **kwargs)

    def is_password_hashed(self, password):
        return password.startswith('pbkdf2_')

    def get_user_location(self):
        try:
            response = requests.get('https://ipinfo.io/json')
            data = response.json()
            return data.get('city', 'Unknown')
        except Exception as e:
            print(f"Error fetching user location: {e}")
            return 'Unknown'
