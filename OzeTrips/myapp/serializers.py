from rest_framework import serializers
from .models import User
from django.core.validators import validate_email
import re
from django.contrib.auth.hashers import make_password

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = ['user_id']  # Exclude user_id from the input fields

    def validate_email(self, value):
        validate_email(value)
        return value

    def validate_phone_number(self, value):
        if not re.match(r'^\+?1?\d{9,15}$', value):
            raise serializers.ValidationError("Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")
        return value

    def validate_pincode(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Pincode must contain only digits.")
        return value

    def validate_name(self, value):
        if not re.match(r'^[a-zA-Z\s]+$', value):
            raise serializers.ValidationError("Name must contain only letters, spaces, and hyphens.")
        return value

    def validate_gender(self, value):
        if not re.match(r'^[a-zA-Z\s-]+$', value):
            raise serializers.ValidationError("Gender must contain only letters, spaces, and hyphens.")
        return value

    def validate_marital_status(self, value):
        if not re.match(r'^[a-zA-Z\s-]+$', value):
            raise serializers.ValidationError("Marital status must contain only letters, spaces, and hyphens.")
        return value

    def validate_address(self, value):
        if not re.match(r'^[a-zA-Z\s-]+$', value):
            raise serializers.ValidationError("Address must contain only letters, spaces, and hyphens.")
        return value

    def validate_state(self, value):
        if not re.match(r'^[a-zA-Z\s-]+$', value):
            raise serializers.ValidationError("State must contain only letters, spaces, and hyphens.")
        return value

    def validate(self, data):
        # Additional validation for fields
        if 'name' in data:
            self.validate_name(data['name'])
        if 'gender' in data:
            self.validate_gender(data['gender'])
        if 'marital_status' in data:
            self.validate_marital_status(data['marital_status'])
        if 'address' in data:
            self.validate_address(data['address'])
        if 'state' in data:
            self.validate_state(data['state'])
        
        if 'password' in data:
            data['password'] = make_password(data['password'])
        return data

    def create(self, validated_data):
        return User.objects.create(**validated_data)
class UpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)