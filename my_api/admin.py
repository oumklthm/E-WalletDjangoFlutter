from django.contrib import admin
from .models import Transaction, Wallet, models


admin.site.register(Wallet)
admin.site.register(Transaction)


# Register your models here.
