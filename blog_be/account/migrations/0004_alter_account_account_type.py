# Generated by Django 4.2.4 on 2024-06-20 17:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0003_alter_account_account_number'),
    ]

    operations = [
        migrations.AlterField(
            model_name='account',
            name='account_type',
            field=models.CharField(choices=[('Saving', 'saving'), ('Current', 'current')], max_length=50),
        ),
    ]
