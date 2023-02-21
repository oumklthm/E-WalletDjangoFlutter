from rest_framework import serializers

from my_api.models import Wallet, Transaction
from django.contrib.auth.models import User

from rest_framework.validators import UniqueTogetherValidator


class WalletGetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['id', 'name', 'slug', 'balance']


class WalletCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['name']


class TransactionGetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ['id', 'wallet', 'transaction_type', 'data',
                  'amount', 'comment']


class TransactionCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ['wallet', 'transaction_type', 'amount', 'comment']

#authantification       

class UserSerializer(serializers.ModelSerializer):
    
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

    class Meta:
        model = User
        fields = (
            'username',
            'first_name',
            'last_name',
            'email',
            'password',
        )
        validators = [
            UniqueTogetherValidator(
                queryset=User.objects.all(),
                fields=['username', 'email']
            )
        ]