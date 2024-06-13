import random
import logging
from django.core.mail import send_mail
from django.contrib.auth import get_user_model, authenticate
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from .serializers import UserSerializer, UpdatePasswordSerializer
from django.contrib.auth.hashers import check_password

User = get_user_model()

# Create a logger
logger = logging.getLogger(__name__)

@api_view(['POST'])
def register_user(request):
    if request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            otp = ''.join(random.choices('0123456789', k=6))
            request.session['otp'] = otp
            request.session['user_id'] = user.user_id  # Use user_id instead of id

            send_otp_email(user.email, otp)

            logger.info(f"User registered successfully: {user.email}")

            return Response({'message': 'User registered successfully. OTP sent to your email.'}, status=status.HTTP_201_CREATED)
        else:
            logger.error(f"Failed to register user: {serializer.errors}")
            return Response({'error': 'Failed to register user', 'details': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

def send_otp_email(email, otp):
    subject = 'OTP Verification'
    message = f'Your OTP for email verification is: {otp}'
    from_email = 'jdnovazen@gmail.com'
    send_mail(subject, message, from_email, [email])

@api_view(['POST'])
def verify_otp(request):
    if request.method == 'POST':
        email = request.data.get('email')
        otp_entered = request.data.get('otp')
        if email and otp_entered:
            try:
                user = User.objects.get(email=email)
                session_otp = request.session.get('otp')
                session_user_id = request.session.get('user_id')

                if session_otp and session_user_id == user.user_id and session_otp == otp_entered:
                    user.email_verified = True
                    user.save()

                    # Clear OTP from session
                    del request.session['otp']
                    del request.session['user_id']

                    logger.info(f"Email verified successfully: {email}")
                    return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)
                else:
                    logger.warning(f"Invalid OTP entered: {otp_entered}")
                    return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                logger.error(f"User not found: {email}")
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            logger.error("Email or OTP not provided")
            return Response({'error': 'Email or OTP not provided'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def login_user(request):
    email = request.data.get('email')
    password = request.data.get('password')
    user = authenticate(email=email, password=password)

    if user is not None:
        token, created = Token.objects.get_or_create(user=user)
        logger.info(f"User logged in successfully: {email}")
        user_id = user.user_identifier  
        return Response({'token': token.key, 'name': user.name, 'user_id': user_id}, status=status.HTTP_200_OK)
    else:
        logger.warning("Invalid credentials")
        return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    request.user.auth_token.delete()
    logger.info(f"User logged out successfully: {request.user.email}")
    return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)

@api_view(['POST', 'PATCH'])  # Support POST for retrieval and PATCH for updating
@permission_classes([IsAuthenticated])
def retrieve_or_update_user(request):
    if request.method == 'POST':
        # Retrieve user
        id = request.data.get('id')
        if id:
            try:
                user = User.objects.get(user_identifier=id)
                serializer = UserSerializer(user)
                response_data = {
                    'name': serializer.data['name'],
                    'birthdate': serializer.data['birthdate'],
                    'phone': serializer.data['phone_number'],
                    'gender': serializer.data['gender'],
                    'state': serializer.data['state'],
                    'pincode': serializer.data['pincode'],
                    'marital_status': serializer.data['marital_status'],
                    'address': serializer.data['address']
                }
                return Response(response_data, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'error': 'ID not provided'}, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'PATCH':
        # Update user
        id = request.data.get('id')
        if id:
            try:
                user = User.objects.get(user_identifier=id)
                serializer = UserSerializer(user, data=request.data, partial=True)  # Allow partial updates
                if serializer.is_valid():
                    serializer.save()
                    return Response({'message': 'User updated successfully'}, status=status.HTTP_200_OK)  # Updated response message
                else:
                    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'error': 'ID not provided'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_password(request):
    if request.method == 'POST':
        serializer = UpdatePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            new_password = serializer.validated_data['new_password']
            user = request.user
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password updated successfully'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
