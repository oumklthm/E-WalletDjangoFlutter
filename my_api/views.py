"""Module with API views."""
from turtle import home
from django.db import transaction as transaction_decorators, utils
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from my_api.models import Wallet, Transaction
from my_api.serializers import (
    WalletGetSerializer,
    WalletCreateUpdateSerializer,
    TransactionGetSerializer,
    TransactionCreateUpdateSerializer,
)
from .serializers import  *
#from django.contrib.auth.decorators import login_required




from .models import *
from .serializers import *
from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework import status
from rest_framework.permissions import IsAdminUser
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed


    



class WalletView(APIView):

    permission_classes = [IsAuthenticated,]
    """Views for operating ``Wallet`` model.
        * GET: list all wallets
        * POST: create a wallet
        * PUT: update a wallet
        * DELETE: delete a wallet
        Only `name` can be set for a wallet,
        `balance` and `slug` have default values.
        Operations Update/Delete require `slug` of a wallet
        as a function argument.
    """

    def get(self, request):
        wallets = Wallet.objects.all()
        serializer = WalletGetSerializer(wallets, many=True)
        return Response(serializer.data)

    def post(self, request):
        wallet = Wallet()
        serializer = WalletCreateUpdateSerializer(wallet, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, slug: str):
        wallet = get_object_or_404(Wallet, slug=slug)
        serializer = WalletCreateUpdateSerializer(wallet, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, slug: str):
        wallet = get_object_or_404(Wallet, slug=slug)
        operation = wallet.delete()
        if operation:
            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class TransactionView(APIView):

    permission_classes = [IsAuthenticated,]
    """Views for operating ``Transaction`` model.
        * GET (get): list all transactions
        * GET (get_by_wallet): list all transaction of a specific wallet
        * POST: create a transaction
        * DELETE: delete a transaction (if it possible)
        Fields `wallet` and `transaction_type` are required,
        other fields have default values.
    """

    def get(self, request):
        transactions = Transaction.objects.all()
        serializer = TransactionGetSerializer(transactions, many=True)
        return Response(serializer.data)

    @staticmethod
    @api_view(['GET', ])
    def get_by_wallet(request, wallet_slug: str):
        if request.method == 'GET':
            wallet = get_object_or_404(Wallet, slug=wallet_slug)
            transactions = Transaction.objects.filter(wallet=wallet)
            serializer = TransactionGetSerializer(transactions, many=True)
            return Response(serializer.data)
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    @transaction_decorators.atomic
    def post(self, request):
        wallet = get_object_or_404(Wallet, name=request.data['wallet'])
        transaction = Transaction(wallet=wallet)
        serializer = TransactionCreateUpdateSerializer(transaction,
                                                       data=request.data)
        if serializer.is_valid():
            transaction = Transaction(**serializer.validated_data)
            transaction.wallet = wallet
            transaction, success = transaction.provide_transaction()
            if success:
                serializer.save()
                return Response(status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, id: int):
        transaction = get_object_or_404(Transaction, id=id)
        try:
            transaction.delete()
        except utils.IntegrityError:
            data = {'details': 'The transaction cannot be deleted.'}
            return Response(status=status.HTTP_400_BAD_REQUEST, data=data)
        return Response(status=status.HTTP_200_OK)
    



@api_view(['POST']) 
def registerWallet(request):
    try:
        username = request.data['username']
        nom = request.data['nom']
        prenom = request.data['prenom']
        password = request.data['password']
        #balance = request.data['balance']
        Numtele = request.data['Numtele']
        

        
    except:
        return Response(
            {"message":"Veuillez fournir tous les données necessaires"},
            status=status.HTTP_200_OK
        )
    if User.objects.filter(username=username).exists(): 
        return Response(
            {
                "message":"already used "
            },
            status=status.HTTP_200_OK
        )
    
    
    user = User.objects.create(username=username,first_name=nom,last_name=prenom)
    user.set_password(password)
    user.save()

    wallet = Wallet.objects.create(user=user)
    #wallet = Wallet.objects.create(user=user,balance=balance)
    wallet.save()
    
    return Response(
        {
            "message":"Créé avec succées" 
        },
        status.HTTP_200_OK
    )

 

class Mytoken(TokenObtainPairView):
    def post(self, request):
        uuu = request.data['username']
        ppp = request.data['password']
        null=None
        u=authenticate(username=uuu,password=ppp) 
        if u is None:
            return Response(
                {
                    'message': 'Donnes invalides',
                },
                status.HTTP_401_UNAUTHORIZED
            )
        refresh = RefreshToken.for_user(u)
        try:
            client = Wallet.objects.get(user=u)
            
            return Response(
                {
                    'token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                    'id':client.id,
                    
                },
                status.HTTP_200_OK
            )
        except:
            return Response(
                {
                    
                    'message': 'Ce compte est inexistant',
                },
                status.HTTP_401_UNAUTHORIZED
            )


