from django.contrib import admin
from .models import *

# Register your models here.


@admin.register(Tractor)
class ModelAdmin(admin.ModelAdmin):
    list_display = ['pk', 'farmer', 'brand']
