# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2018-12-17 20:05
from __future__ import unicode_literals

from django.db import migrations

from oidc_provider.lib.utils.token import hash_token


def calculate_hashes(apps, schema_editor):
    Token = apps.get_model('oidc_provider', 'Token')
    token_qs = Token.objects.values_list('id', 'access_token', 'refresh_token')
    for _id, access_token, refresh_token in token_qs.iterator():
        Token.objects.filter(id=_id).update(
            access_token_hash=hash_token(access_token),
            refresh_token_hash=hash_token(refresh_token),
        )


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0031_token_lookup_hash_part_1_of_3'),
    ]

    operations = [
        migrations.RunPython(calculate_hashes, reverse_code=noop),
    ]
