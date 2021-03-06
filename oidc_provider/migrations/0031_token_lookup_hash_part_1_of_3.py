# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2018-12-17 20:04
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0030_change_response_types_field_3_of_3'),
    ]

    operations = [
        migrations.AddField(
            model_name='token',
            name='access_token_hash',
            field=models.CharField(help_text='Hashed version of the token for fast database lookups.', max_length=255, null=True, unique=True, verbose_name='Access Token Lookup'),
        ),
        migrations.AddField(
            model_name='token',
            name='refresh_token_hash',
            field=models.CharField(help_text='Hashed version of the token for fast database lookups.', max_length=255, null=True, unique=True, verbose_name='Refresh Token Lookup'),
        ),
        migrations.AlterField(
            model_name='token',
            name='access_token',
            field=models.TextField(verbose_name='Access Token'),
        ),
        migrations.AlterField(
            model_name='token',
            name='refresh_token',
            field=models.TextField(verbose_name='Refresh Token'),
        ),
    ]
