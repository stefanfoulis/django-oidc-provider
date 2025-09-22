from unittest import mock

import pytest
from django.utils import timezone

from oidc_provider.fields_encrypted_ciphers import Aes256GcmHkdfCipher
from oidc_provider.fields_encrypted_ciphers import CipherRegistry
from oidc_provider.fields_encrypted_ciphers import PlaintextCipher
from oidc_provider.fields_encrypted_utils import rollover_encryption_keys
from oidc_provider.models import Client
from oidc_provider.models import RSAKey
from oidc_provider.models import Token


@pytest.mark.django_db
def test_key_rollover():
    plain_registry = CipherRegistry()
    plain_registry.set_encryption_cipher(PlaintextCipher())
    encrypted1_registry = CipherRegistry()
    encrypted1_registry.set_encryption_cipher(Aes256GcmHkdfCipher(kid="key1", secret_key="secret1"))
    encrypted1_registry.add_cipher(PlaintextCipher())
    encrypted2_registry = CipherRegistry()
    encrypted2_registry.set_encryption_cipher(Aes256GcmHkdfCipher(kid="key2", secret_key="secret2"))
    encrypted2_registry.add_cipher(Aes256GcmHkdfCipher(kid="key1", secret_key="secret1"))
    encrypted2_registry.add_cipher(PlaintextCipher())

    secret1 = "secret-1"
    secret2 = "secret-2"
    secret3 = "secret-3"

    with mock.patch("oidc_provider.fields_encrypted.cipher_registry", plain_registry):
        plain_client = Client.objects.create(
            client_id="c1", client_secret=secret1, response_types=["id_token token"]
        )
    with mock.patch("oidc_provider.fields_encrypted.cipher_registry", encrypted1_registry):
        enc1_client = Client.objects.create(
            client_id="c2", client_secret=secret2, response_types=["id_token token"]
        )
    with mock.patch("oidc_provider.fields_encrypted.cipher_registry", encrypted2_registry):
        enc2_client = Client.objects.create(
            client_id="c3", client_secret=secret3, response_types=["id_token token"]
        )

    def client_qs(kid: str):
        return Client.objects.filter(client_secret__kid=kid)

    assert client_qs(plain_registry.encryption_cipher.kid).count() == 1
    assert client_qs(encrypted1_registry.encryption_cipher.kid).count() == 1
    assert client_qs(encrypted2_registry.encryption_cipher.kid).count() == 1

    with mock.patch("oidc_provider.fields_encrypted.cipher_registry", encrypted2_registry):
        rollover_encryption_keys(model=Client, fieldname="client_secret")

        assert client_qs(plain_registry.encryption_cipher.kid).count() == 0
        assert client_qs(encrypted1_registry.encryption_cipher.kid).count() == 0
        assert client_qs(encrypted2_registry.encryption_cipher.kid).count() == 3

        assert Client.objects.get(id=plain_client.id).client_secret == secret1
        assert Client.objects.get(id=enc1_client.id).client_secret == secret2
        assert Client.objects.get(id=enc2_client.id).client_secret == secret3


@pytest.mark.django_db
def test_rollover_all_keys():
    plain_registry = CipherRegistry()
    plain_registry.set_encryption_cipher(PlaintextCipher())
    encrypted_registry = CipherRegistry()
    encrypted_registry.set_encryption_cipher(Aes256GcmHkdfCipher(kid="key1", secret_key="secret1"))
    encrypted_registry.add_cipher(PlaintextCipher())

    combinations = [
        (Client, "client_secret"),
        (Token, "access_token"),
        (Token, "refresh_token"),
        (RSAKey, "key"),
    ]
    secret = "secret1"
    with mock.patch("oidc_provider.fields_encrypted.cipher_registry", plain_registry):
        client = Client.objects.create(client_id="c1", client_secret=secret)
        Token.objects.create(
            user=None,
            access_token=secret,
            refresh_token=secret,
            expires_at=timezone.now(),
            client=client,
        )
        RSAKey.objects.create(key="key1")

        for model, field in combinations:
            assert (
                model.objects.filter(
                    **{f"{field}__kid": plain_registry.encryption_cipher.kid}
                ).count()
                == 1
            )

    with mock.patch("oidc_provider.fields_encrypted.cipher_registry", encrypted_registry):
        from oidc_provider.fields_encrypted_utils import rollover_all_encryption_keys

        rollover_all_encryption_keys()

        for model, field in combinations:
            assert (
                model.objects.filter(
                    **{f"{field}__kid": encrypted_registry.encryption_cipher.kid}
                ).count()
                == 1
            )
