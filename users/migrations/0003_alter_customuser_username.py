# Generated by Django 5.1.6 on 2025-03-11 09:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_alter_customuser_is_active'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='username',
            field=models.CharField(max_length=255, unique=True),
        ),
    ]
