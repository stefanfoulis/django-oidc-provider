# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2018-12-07 14:12
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0026_client_multiple_response_types'),
    ]

    operations = [
        # We've reverted this change. Since this migration did not change anything at db
        # level, it is safe to remove the operations below.

        # migrations.AlterField(
        #     model_name='client',
        #     name='owner',
        #     field=models.ForeignKey(blank=True, default=None, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='oidc_provider_client_set', to=settings.AUTH_USER_MODEL, verbose_name='Owner'),
        # ),
        # migrations.AlterField(
        #     model_name='client',
        #     name='response_types',
        #     field=models.ManyToManyField(related_name='oidc_provider_client_set', to='oidc_provider.ResponseType'),
        # ),
    ]
