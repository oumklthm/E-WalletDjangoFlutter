from django.urls import path
from my_api.views import WalletView,TransactionView
# from api import views


from .views import Mytoken, registerWallet

app_name = 'my_api'

urlpatterns = [
    path('wallets', WalletView.as_view(), name='get-wallets'),
    path('wallets', WalletView.as_view(), name='create-wallet'),
    path('wallets/<str:slug>', WalletView.as_view(), name='update-wallet'),
    path('wallets/<str:slug>', WalletView.as_view(), name='delete-wallet'),
    path('transactions', TransactionView.as_view(), name='get-transactions'),
    path('transactions/<int:id>', TransactionView.as_view(),
         name='delete-transactions'),
    path('transactions/<str:wallet_slug>', TransactionView.get_by_wallet,
         name='get-transactions-by-wallet'),
    path('transactions', TransactionView.as_view(), name='create-transaction'),
    path('login/', Mytoken.as_view(), name='login to us'), 
    path("register/", registerWallet, name="Register"), 


   



]

