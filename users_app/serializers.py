from rest_framework import serializers
from .utils import Util
from .models import User
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


class RegisterSerializer(serializers.ModelSerializer):
    password=serializers.CharField(
        max_length=20,
        min_length=6,
        write_only=True,
    )
    class Meta:
        model=User
        fields = [
            'email',
            'username',
            'password',
        ]

    # Here we validating data from RegisterApi post
    def validate(self, attrs):
        email=attrs.get('email', '')
        username=attrs.get('username', '')

        if not username.isalnum():
            raise serializers.ValidationError('The username should contains only alphanumeric character')

        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)  


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = '__all__'    


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=999)

    class Meta:
        model = User
        fields = ['token']            


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    username = serializers.CharField(
        max_length=255, 
        min_length=3, 
        read_only=True,
    )
    password = serializers.CharField(
        max_length=20,
        min_length=6,
        write_only=True,
    )      

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        # user = User.objects.filter(email=email).first()
        user = User.objects.get(email=email)
        user.is_active = True
        user.save()
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')  

        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens
        }

        return super().validate(attrs)    


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer): 
    password = serializers.CharField(
        max_length=20,
        min_length=6,
        write_only=True,
    )
    # token = serializers.CharField(
    #     min_length=1, 
    # )
    uidb64 = serializers.CharField(
        min_length=1, 
    )

    class Meta:
        fields = ['password', 'uidb64'] # 'token'

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            # token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            user.set_password(password)
            user.save()
            # if not PasswordResetTokenGenerator().check_token(user, token):
            #     raise AuthenticationFailed('The reset link is invalid', 401)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)