# Generated by Django 4.1.3 on 2022-11-13 08:07

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("krishikhoj", "0002_tractor_name"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="tractor",
            name="id",
        ),
        migrations.AddField(
            model_name="tractor",
            name="trac_id",
            field=models.UUIDField(
                default=uuid.UUID("e9160077-4fa3-4147-b3fc-e6a4d2625cf5"),
                editable=False,
                primary_key=True,
                serialize=False,
            ),
        ),
    ]
