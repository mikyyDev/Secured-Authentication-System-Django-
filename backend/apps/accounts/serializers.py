from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import (
    validate_password as django_validate_password,
)
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from rest_framework import serializers

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "email_verified")
        read_only_fields = fields


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        trim_whitespace=False,
    )

    password_confirmation = serializers.CharField(
        write_only=True,
        required=True,
        trim_whitespace=False,
    )

    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "password",
            "password_confirmation",
        )

    def validate_username(self, value):
        value = value.strip()

        if not value:
            raise serializers.ValidationError(
                "Username cannot be empty."
            )

        if len(value) < 3:
            raise serializers.ValidationError(
                "Username must be at least 3 characters."
            )

        return value

    def validate_email(self, value):
        return value.strip().lower()

    def validate_password(self, value):
        try:
            django_validate_password(value)
        except DjangoValidationError as error:
            raise serializers.ValidationError(error.messages) from error

        return value

    def validate(self, attrs):
        password = attrs["password"]
        password_confirmation = attrs["password_confirmation"]

        if password != password_confirmation:
            raise serializers.ValidationError({
                "password_confirmation": "Passwords do not match."
            })

        return attrs

    @transaction.atomic
    def create(self, validated_data):
        validated_data.pop("password_confirmation")
        password = validated_data.pop("password")
        user = User.objects.create_user(
            password=password,
            **validated_data,
            )
        return user