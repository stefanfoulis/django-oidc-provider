from django.db.models import Q

from . import fields_encrypted
from .models import Client
from .models import RSAKey
from .models import Token


def rollover_all_encryption_keys():
    """
    Rollover all encryption keys, re-encrypting all data with the latest key.
    """
    rollover_encryption_keys(model=Client, fieldname="client_secret")
    rollover_encryption_keys(model=Token, fieldname="access_token")
    rollover_encryption_keys(model=Token, fieldname="refresh_token")
    rollover_encryption_keys(model=RSAKey, fieldname="key")


def rollover_encryption_keys(model, fieldname):
    """
    Rollover encryption key for a specific model field, re-encrypting all data
    with the latest key.
    """
    cipher = fields_encrypted.cipher_registry.encryption_cipher
    qs = model.objects.filter(
        Q(**{f"{fieldname}__isnull": False}) & ~Q(**{f"{fieldname}__kid": cipher.kid})
    )
    for obj in qs.iterator():
        setattr(obj, fieldname, getattr(obj, fieldname))  # Trigger re-encryption
        obj.save(update_fields=[fieldname])
