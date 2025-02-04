# Generated by Django 3.1 on 2020-08-07 11:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Users', '0009_auto_20200807_1431'),
    ]

    operations = [
        migrations.AlterField(
            model_name='doctor',
            name='hospital',
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AlterField(
            model_name='doctor',
            name='specialization',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AlterField(
            model_name='patient',
            name='Weight',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='patient',
            name='age',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='patient',
            name='blood_group',
            field=models.CharField(blank=True, max_length=3, null=True),
        ),
        migrations.AlterField(
            model_name='patient',
            name='blood_pressure',
            field=models.CharField(blank=True, max_length=10, null=True),
        ),
        migrations.AlterField(
            model_name='patient',
            name='bmi',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='patient',
            name='height',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='patient',
            name='setbacks',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
    ]
