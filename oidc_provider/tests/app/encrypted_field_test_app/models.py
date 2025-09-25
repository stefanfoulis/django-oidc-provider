from django.db import models

from oidc_provider.fields_encrypted import EncryptedTextField


class ExampleModel(models.Model):
    """Example model for testing EncryptedTextField dumpdata/loaddata functionality."""

    name = models.CharField(max_length=100)
    secret = EncryptedTextField()
    created = models.DateField(null=True)

    class Meta:
        app_label = "encrypted_field_test_app"

    def __str__(self):
        return f"ExampleModel({self.name})"
