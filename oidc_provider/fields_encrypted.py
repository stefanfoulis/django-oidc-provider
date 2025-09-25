import base64
import copy
import json

from django import forms
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.query_utils import DeferredAttribute

from . import settings
from .fields_encrypted_ciphers import Cipher

cipher_registry = settings.get("OIDC_DB_CIPHER_REGISTRY", import_str=True)


class EncryptionDataFromDbWrapper(dict):
    """
    A simple wrapper around a dict be able to distinguish data that comes
    from the database from data that was assigned to the field.
    """

    pass


class EncryptedDataDescriptor(DeferredAttribute):
    """
    The main descriptor for EncryptedTextField that transparently returns the decrypted
    plaintext value as a string and deals with the assignment of plaintext strings.
    """

    def __init__(self, field):
        super().__init__(field)

    def __get__(self, instance, cls=None):
        if instance is None:
            return self

        # In super() django either returns the raw value from field.__dict__ or
        # fetches it from the database, if it was initially deferred.
        # raw_data is the raw value from the database.
        raw_data = super().__get__(instance, cls)

        if raw_data is None:
            # This means the field is NULL in the database. In that case there is no
            # data to encrypt or decrypt, so we just return None.
            return None

        if isinstance(raw_data, dict):
            if "new_plaintext" in raw_data:
                # This means the field was assigned a new plaintext value.
                # We can just return the plaintext value.
                return raw_data["new_plaintext"]
            elif "plaintext" in raw_data:
                # This means the field was already decrypted before and we cached
                # the plaintext value. We can just return it.
                return raw_data["plaintext"]
            elif "ciphertext" in raw_data:
                # This means the field contains encrypted data, so we need to decrypt it.
                # And cache the plaintext value for future accesses.
                plaintext = self.field.decrypt(raw_data)
                raw_data["plaintext"] = plaintext
                return plaintext
        # This should not happen, unknown state.
        raise ValueError(f"Invalid data for EncryptedTextField: unexpected type {type(raw_data)}")

    def __set__(self, instance, value):
        if value is None:
            # Setting to None means we want to store NULL in the database as well.
            # This means the field is "empty", so no need to encrypt anything.
            instance.__dict__[self.field.name] = None
        elif isinstance(value, str):
            # Setting to a string means we want to store a new plaintext value.
            # We store it in the raw_data for later encryption on save.
            instance.__dict__[self.field.name] = {"new_plaintext": value}

        elif isinstance(value, EncryptionDataFromDbWrapper):
            # This means django is setting the value when loading stuff from
            # the database.
            # Convert it back to a normal dict here, so subsecquent code can handle
            # it normally.
            instance.__dict__[self.field.name] = dict(value)

        elif isinstance(value, dict):
            # Unfortunatly django assigns the raw dict when loading from fixtures, so
            # we need to handle that as well.
            # We just accept it as-is, so it will be handled properly on save.
            instance.__dict__[self.field.name] = value
        else:
            # This is not allowed.
            raise ValueError(
                f"Invalid data for EncryptedTextField, can't set value of type {type(value)}"
            )


class JSONEncoderWithBytesSupport(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return {"__bytes__": base64.b64encode(obj).decode("utf-8")}
        return super().default(obj)


class JSONDecoderWithBytesSupport(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, dct):
        if isinstance(dct, dict) and "__bytes__" in dct and len(dct) == 1:
            return base64.b64decode(dct["__bytes__"])
        return dct


class EncryptedTextField(models.JSONField):
    descriptor_class = EncryptedDataDescriptor

    def __init__(self, **kwargs):
        kwargs.setdefault("null", True)  # Allow None values
        kwargs.setdefault("encoder", JSONEncoderWithBytesSupport)
        kwargs.setdefault("decoder", JSONDecoderWithBytesSupport)
        super().__init__(**kwargs)

    def contribute_to_class(self, cls, name, **kwargs):
        super().contribute_to_class(cls, name, **kwargs)
        setattr(cls, self.attname, self.descriptor_class(self))

    def encrypt(self, value, cipher=None) -> dict:
        cipher = cipher_registry.encryption_cipher if cipher is None else cipher
        return {
            "ciphertext": cipher.encrypt(value),
            "kid": cipher.kid,
            "alg": cipher.alg,
        }

    def decrypt(self, metadata: dict) -> str:
        if not (cipher := self._pick_cipher(metadata)):
            raise ValueError(
                f"No suitable cipher found for decryption of field '{self.name}' and value '{metadata}'"
            )
        return cipher.decrypt(metadata["ciphertext"])

    def _pick_cipher(self, metadata: dict) -> Cipher | None:
        """
        Pick the right cipher based on the metadata.
        """
        if metadata is None:
            return None

        if (kid := metadata.get("kid", None)) is None:
            return None

        alg = metadata.get("alg", None)

        return cipher_registry.pick_cipher(kid=kid, alg=alg)

    def from_db_value(self, value, expression, connection):
        db_value = super().from_db_value(value, expression, connection)
        if db_value is None:
            return None
        if isinstance(db_value, dict):
            # This is the encryption metatdata dict we expect.
            # We wrap it here, so we can handle it properly in the descriptor.
            return EncryptionDataFromDbWrapper(db_value)
        return super().from_db_value(value, expression, connection)

    def to_python(self, value):
        """Convert the database value to a Python value."""
        if value is None:
            return None

        # Return dict as-is (will be handled by descriptor)
        if isinstance(value, dict):
            return value

        if isinstance(value, str):
            # This means the field contains plaintext data, so not encrypted.
            # We can just return it as a dict with "new_plaintext" for the descriptor.
            return {"new_plaintext": value}
        raise ValidationError(f"Invalid value for EncryptedTextField '{value}' {type(value)}")

    def value_to_string(self, obj):
        """
        Used when serializing (dumpdata). Returns the encrypted metadata instead of plaintext.
        This method is specifically called by Django's serialization framework.
        """
        # Use the same logic as pre_save() to get properly encrypted data for serialization
        # This handles all cases: new objects, saved objects, key rollover, etc.
        encrypted_value = self.pre_save(obj, add=obj.pk is None)
        return self.get_prep_value(encrypted_value)

    def pre_save(self, model_instance, add):
        """
        Called before saving to handle encryption.
        """
        # Get the current raw value from the instance's __dict__
        value = model_instance.__dict__.get(self.attname)
        if value is None:
            return None

        if isinstance(value, dict):
            cipher = cipher_registry.encryption_cipher
            if "new_plaintext" in value:
                # A new value was set, so we need to encrypt it. Anything else
                # previously in the metadata is now obsolete anyway, so we discard it.
                return self.encrypt(value["new_plaintext"])
            elif "ciphertext" in value and "kid" in value and value["kid"] != cipher.kid:
                # If the "kid" is different than the currently expected encryption kid,
                # we need to re-encrypt/rollover.
                plaintext = self._pick_cipher(value).decrypt(value["ciphertext"])
                return self.encrypt(plaintext)
            else:
                # Nothing really changed. We just need to make sure we don't store the
                # cached plaintext in the database, so we remove it from the dict.
                value = copy.deepcopy(value)
                value.pop("plaintext", None)
                return value

        # For other values, use normal processing
        return super().pre_save(model_instance, add)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        # We don't need anything about our custom field in the context of the migration.
        # It keep things much simpler, if the migrations think this is just a boring
        # plain old JSONField.
        # See `def clone()` for more information.
        path = "django.db.models.JSONField"
        return name, path, args, kwargs

    def clone(self):
        name, path, args, kwargs = self.deconstruct()
        # Usually the Field base class would do `self.__class__(*args, **kwargs)` here.
        # However we want to pretend to migrations that we're just a normal JSONField,
        # so that is what we return here.
        # We also remove a bunch of kwargs that are not relevant in the migrations.
        kwargs = copy.deepcopy(kwargs)
        kwargs.pop("verbose_name", None)
        kwargs.pop("help_text", None)
        kwargs.pop("choices", None)
        kwargs.pop("encoder", None)
        kwargs.pop("decoder", None)
        return models.JSONField(*args, **kwargs)

    def validate(self, value, model_instance):
        # This is called for model validate. We are pretending to be like a text field,
        # even though we're storing to JSON under the hood.
        # So we can't call super() here, because that would do JSON validation.
        # So we're calling super of the parent class of JSONField instead, which just
        # does the basic validation.
        super(models.JSONField, self).validate(value, model_instance)

    def formfield(self, **kwargs):
        return super(models.JSONField, self).formfield(
            **{
                "form_class": forms.CharField,
                "widget": forms.Textarea,
                **kwargs,
            }
        )
