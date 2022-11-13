from django.db import models
from django.contrib.auth.models import User
import uuid

# Create your models here.


class Tractor(models.Model):

    # Relational Model
    farmer = models.ForeignKey(User, on_delete=models.CASCADE)

    brand = models.CharField(max_length=100, blank=False)
    naming = models.CharField(max_length=300, blank=False)
    drivers_seat = models.CharField(max_length=100, blank=False)
    cab_suspension = models.CharField(max_length=100, blank=False)
    front_axle_suspension = models.BooleanField(blank=False)
    wheel_drive = models.CharField(max_length=10, blank=False)
    gear_box_type = models.CharField(max_length=50, blank=False)

    # main one
    implementations = models.TextField(blank=False)

    # Max Engine Speed
    rpm = models.IntegerField(blank=False)

    # Front power takeoff
    pto = models.BooleanField(blank=False)

    # Tractor Id
    trac_id = models.UUIDField(
        default=uuid.uuid4(), editable=False, primary_key=True)
