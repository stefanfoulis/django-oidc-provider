# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2018-12-16 02:43
from __future__ import unicode_literals

from django.db import migrations, models
import oidc_provider.fields


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0027_swappable_client_model'),
    ]

    operations = [
        migrations.RenameField(
            model_name='client',
            old_name='response_types',
            new_name='old_response_types',
        ),
        migrations.AddField(
            model_name='client',
            name='response_types',
            field=oidc_provider.fields.JsonMultiSelectModelField(choices=[('code', 'code (Authorization Code Flow)'), ('id_token', 'id_token (Implicit Flow)'), ('id_token token', 'id_token token (Implicit Flow)'), ('code token', 'code token (Hybrid Flow)'), ('code id_token', 'code id_token (Hybrid Flow)'), ('code id_token token', 'code id_token token (Hybrid Flow)')], default=set, verbose_name='Response Types'),
        ),
    ]