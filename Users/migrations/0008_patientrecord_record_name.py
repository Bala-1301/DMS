# Generated by Django 3.0.5 on 2020-07-30 10:52

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('Users', '0007_auto_20200726_1745'),
    ]

    operations = [
        migrations.AddField(
            model_name='patientrecord',
            name='record_name',
            field=models.CharField(default=django.utils.timezone.now, max_length=150),
            preserve_default=False,
        ),
    ]
