# Generated by Django 3.0.5 on 2020-07-20 12:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Users', '0002_auto_20200716_1945'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='user_type',
            field=models.CharField(choices=[('Doctor', 'DOCTOR'), ('Patient', 'PATIENT'), ('Admin', 'ADMIN')], default=None, max_length=7),
        ),
    ]
