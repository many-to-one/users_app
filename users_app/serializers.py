from rest_framework import serializers
from .models import User


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