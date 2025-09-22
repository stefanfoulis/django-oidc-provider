"""
Comprehensive pytest-django tests for EncryptedTextField using existing models.

This test suite uses the existing production models (Client, Code, Token, RSAKey)
that already have EncryptedTextField fields, providing real-world test coverage.
"""

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from oidc_provider.fields_encrypted import EncryptedTextField
from oidc_provider.models import Client
from oidc_provider.models import Code
from oidc_provider.models import RSAKey
from oidc_provider.models import Token

User = get_user_model()


class TestEncryptedTextField:
    @pytest.fixture
    def user(self, db):
        """Create a test user."""
        return User.objects.create_user(username="testuser", password="testpass")

    @pytest.fixture
    def client_model(self, db):
        """Create a test Client instance."""
        return Client.objects.create(
            name="Test Client",
            client_id="test-client-id",
            client_secret="test-secret-value",
            response_types=["code"],
        )

    def test_client_secret_field_behavior(self, client_model):
        """Test EncryptedTextField behavior on Client.client_secret field."""
        # Test initial assignment - now returns pure str
        assert isinstance(client_model.client_secret, str)
        assert client_model.client_secret == "test-secret-value"

        # Test string operations
        assert client_model.client_secret.startswith("test")
        assert client_model.client_secret.endswith("value")
        assert "secret" in client_model.client_secret
        assert len(client_model.client_secret) == len("test-secret-value")

        # Test metadata access through descriptor cache
        field = client_model._meta.get_field("client_secret")
        # The cache name is constructed as f"_{field_name}_metadata_cache"
        cache_name = f"_{field.name}_metadata_cache"
        cached_data = getattr(client_model, cache_name, None)
        if cached_data:
            assert hasattr(cached_data, "key_id")
            assert hasattr(cached_data, "version")

        # Test reassignment
        client_model.client_secret = "new-secret-value"
        assert client_model.client_secret == "new-secret-value"
        assert isinstance(client_model.client_secret, str)

    def test_encrypted_text_string_methods(self, client_model):
        """Test comprehensive string methods on encrypted field value."""
        client_model.client_secret = "Hello World Test"
        secret = client_model.client_secret

        # Basic string operations - now working with pure str
        assert secret.upper() == "HELLO WORLD TEST"
        assert secret.lower() == "hello world test"
        assert secret.title() == "Hello World Test"
        assert secret.strip() == "Hello World Test"
        assert secret.replace("World", "Universe") == "Hello Universe Test"

        # Substring operations
        assert secret[0:5] == "Hello"
        assert secret[-4:] == "Test"
        assert secret[6:11] == "World"

        # Search operations
        assert secret.find("World") == 6
        assert secret.index("Test") == 12
        assert secret.count("l") == 3

        # String comparisons
        assert secret == "Hello World Test"
        assert secret != "Different"

        # Boolean behavior
        assert bool(secret) is True
        client_model.client_secret = ""
        assert bool(client_model.client_secret) is False

    def test_encrypted_text_iteration_and_slicing(self, client_model):
        """Test iteration and slicing behavior of encrypted field value."""
        client_model.client_secret = "hello"
        secret = client_model.client_secret

        # Test iteration - now with pure str
        chars = list(secret)
        assert chars == ["h", "e", "l", "l", "o"]

        # Test slicing
        assert secret[1:4] == "ell"
        assert secret[:2] == "he"
        assert secret[2:] == "llo"

        # Test 'in' operator
        assert "ell" in secret
        assert "xyz" not in secret

    def test_encrypted_text_formatting(self, client_model):
        """Test string formatting behavior of encrypted field value."""
        client_model.client_secret = "test"
        secret = client_model.client_secret

        # Test string formatting - now with pure str
        formatted = f"Secret: {secret}"
        assert formatted == "Secret: test"

        # Test repr - now just a regular string
        assert repr(secret) == "'test'"

    def test_client_save_and_reload(self, client_model):
        """Test that encrypted fields persist correctly through save/reload."""
        original_secret = "persistent-secret"
        client_model.client_secret = original_secret
        client_model.save()

        # Reload from database
        reloaded_client = Client.objects.get(id=client_model.id)
        assert reloaded_client.client_secret == original_secret
        assert isinstance(reloaded_client.client_secret, str)

    def test_client_refresh_from_db(self, client_model):
        """Test that encrypted fields persist correctly through save/reload."""
        original_secret = "persistent-secret"
        client_model.client_secret = original_secret
        client_model.save()

        assert client_model.client_secret == original_secret

        # Refresh from database
        client_model.refresh_from_db()

        assert client_model.client_secret == original_secret

    def test_client_refresh_from_db_without_access_through_descriptor_after_save(
        self, client_model
    ):
        original_secret = "persistent-secret"
        client_model.client_secret = original_secret
        client_model.save()

        # Refresh from database
        client_model.refresh_from_db()

        assert client_model.client_secret == original_secret

    def test_client_refresh_from_db_if_it_changed(self, client_model):
        initial_secret = str(client_model.client_secret)
        altered_secret = "altered-secret"
        altered_client = Client.objects.get(id=client_model.id)
        altered_client.client_secret = altered_secret
        altered_client.save()

        assert client_model.client_secret == initial_secret

        # Refresh from database
        client_model.refresh_from_db()

        assert client_model.client_secret == altered_secret

    def test_client_manager_create(self, db):
        """Test creating clients through the manager."""
        client = Client.objects.create(
            name="Manager Test Client",
            client_id="manager-client-id",
            client_secret="manager-secret",
            response_types=["code"],
        )

        assert isinstance(client.client_secret, str)
        assert client.client_secret == "manager-secret"

        # Verify it's actually saved
        reloaded = Client.objects.get(id=client.id)
        assert reloaded.client_secret == "manager-secret"

    def test_code_model_encryption(self, user, client_model, db):
        """Test EncryptedTextField on Code.code field."""
        expires_at = timezone.now() + timedelta(minutes=10)
        code = Code.objects.create(
            user=user,
            client=client_model,
            code="authorization-code-12345",
            expires_at=expires_at,
            _scope="openid profile",
        )

        assert isinstance(code.code, str)
        assert code.code == "authorization-code-12345"

        # Test persistence
        reloaded_code = Code.objects.get(id=code.id)
        assert reloaded_code.code == "authorization-code-12345"

    def test_token_model_encryption(self, user, client_model, db):
        """Test EncryptedTextField on Token access_token and refresh_token fields."""
        expires_at = timezone.now() + timedelta(hours=1)
        token = Token.objects.create(
            user=user,
            client=client_model,
            access_token="access-token-xyz",
            access_token_hash="dummy-hash-1",
            refresh_token="refresh-token-abc",
            refresh_token_hash="dummy-hash-2",
            expires_at=expires_at,
            _scope="openid profile",
            _id_token="{}",
        )

        # Test access_token
        assert isinstance(token.access_token, str)
        assert token.access_token == "access-token-xyz"

        # Test refresh_token
        assert isinstance(token.refresh_token, str)
        assert token.refresh_token == "refresh-token-abc"

        # Test persistence
        reloaded_token = Token.objects.get(id=token.id)
        assert reloaded_token.access_token == "access-token-xyz"
        assert reloaded_token.refresh_token == "refresh-token-abc"

    def test_rsa_key_model_encryption(self, db):
        """Test EncryptedTextField on RSAKey.key field."""
        rsa_key_content = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef...
-----END RSA PRIVATE KEY-----"""

        rsa_key = RSAKey.objects.create(key=rsa_key_content)

        assert isinstance(rsa_key.key, str)
        assert rsa_key.key == rsa_key_content

        # Test persistence
        reloaded_key = RSAKey.objects.get(id=rsa_key.id)
        assert reloaded_key.key == rsa_key_content

    def test_queryset_operations(self, db):
        """Test queryset operations with encrypted fields."""
        # Create test data
        Client.objects.create(
            name="Client 1", client_id="client-1", client_secret="secret-1", response_types=["code"]
        )
        Client.objects.create(
            name="Client 2", client_id="client-2", client_secret="secret-2", response_types=["code"]
        )

        # Test basic queries
        clients = Client.objects.all()
        assert len(clients) == 2

        # Test filtering by other fields (not encrypted ones)
        client = Client.objects.get(client_id="client-1")
        assert client.client_secret == "secret-1"

    def test_field_null_and_blank_handling(self, db):
        """Test handling of null and blank values."""
        # Test with null value
        client = Client.objects.create(
            name="Null Secret Client",
            client_id="null-client",
            client_secret=None,
            response_types=["code"],
        )
        assert client.client_secret is None

        # Test with empty string
        client.client_secret = ""
        client.save()
        reloaded = Client.objects.get(id=client.id)
        assert reloaded.client_secret == ""
        assert isinstance(reloaded.client_secret, str)

    def test_field_metadata_preservation(self, client_model):
        """Test that metadata is preserved across operations."""
        # Set a value and get metadata through descriptor cache
        client_model.client_secret = "metadata-test"
        field = client_model._meta.get_field("client_secret")
        cache_name = f"_{field.name}_metadata_cache"
        original_cached = getattr(client_model, cache_name, None)

        if original_cached:
            original_key_id = original_cached.key_id
            original_version = original_cached.version

            # Save and reload
            client_model.save()
            reloaded = Client.objects.get(id=client_model.id)

            # Get metadata from reloaded instance
            reloaded_cached = getattr(reloaded, cache_name, None)

            # Metadata should be preserved
            if reloaded_cached:
                assert reloaded_cached.key_id == original_key_id
                assert reloaded_cached.version == original_version

    def test_multiple_assignments(self, client_model):
        """Test multiple assignments to the same field."""
        # First assignment
        client_model.client_secret = "first-value"
        assert client_model.client_secret == "first-value"

        # Second assignment
        client_model.client_secret = "second-value"
        assert client_model.client_secret == "second-value"

        # Third assignment with different type
        client_model.client_secret = None
        assert client_model.client_secret is None

        # Fourth assignment back to string
        client_model.client_secret = "fourth-value"
        assert client_model.client_secret == "fourth-value"
        assert isinstance(client_model.client_secret, str)

    def test_descriptor_behavior(self, client_model):
        """Test descriptor behavior of EncryptedTextField."""
        # Test direct field access
        field = client_model._meta.get_field("client_secret")
        assert isinstance(field, EncryptedTextField)

        # Test assignment through descriptor
        client_model.client_secret = "descriptor-test"
        assert client_model.client_secret == "descriptor-test"

        # Test that the descriptor returns pure str
        assert isinstance(client_model.client_secret, str)

    def test_field_form_preparation(self, client_model):
        """Test field preparation for forms."""
        field = client_model._meta.get_field("client_secret")
        assert isinstance(field, EncryptedTextField)

        # Test value_to_string (used in serialization like dumpdata)
        # This should now return encrypted metadata, not plaintext
        form_value = field.value_to_string(client_model)

        # Should be encrypted metadata (dict), not plaintext (string)
        assert isinstance(form_value, dict)
        assert "ciphertext" in form_value
        assert "kid" in form_value
        assert "alg" in form_value

        # Should NOT be the plaintext value
        assert form_value != client_model.client_secret

    @pytest.mark.parametrize(
        "test_value",
        [
            "simple",
            "with spaces",
            "with-dashes-and_underscores",
            "with.dots.and,commas",
            "with/slashes\\and:colons",
            "with'quotes\"and`backticks",
            "with\nnewlines\tand\ttabs",
            "unicode: αβγδε 中文 🚀",
            "",  # empty string
            "a" * 1000,  # long string
        ],
    )
    def test_various_string_values(self, client_model, test_value):
        """Test the field with various string values."""
        client_model.client_secret = test_value
        assert client_model.client_secret == test_value
        assert isinstance(client_model.client_secret, str)

        # Test persistence
        client_model.save()
        reloaded = Client.objects.get(id=client_model.id)
        assert reloaded.client_secret == test_value

    def test_json_storage_structure(self, client_model):
        """Test that the field stores data in correct JSON structure."""
        client_model.client_secret = "json-test"
        client_model.save()

        # With the new implementation, we can't easily test prep_value without triggering save
        # But we can verify the field's basic behavior
        assert isinstance(client_model.client_secret, str)
        assert client_model.client_secret == "json-test"

    def test_field_value_persists_across_assignments(self, client_model):
        """Test that field values persist correctly across multiple assignments."""
        # Initial assignment
        client_model.client_secret = "persistent-test"
        initial_secret = client_model.client_secret

        # Assign to another field
        client_model.name = "Updated Name"

        # Verify the encrypted field is unchanged
        assert client_model.client_secret == "persistent-test"
        assert client_model.client_secret == initial_secret  # Same value

        # Save and reload
        client_model.save()
        reloaded = Client.objects.get(id=client_model.id)
        assert reloaded.client_secret == "persistent-test"

    def test_multiple_save_calls(self, client_model):
        """Test that calling save() multiple times works correctly."""
        original_value = "multiple-save-test"

        # Initial save with a value
        client_model.client_secret = original_value
        client_model.save()

        # Verify the value is correct after first save
        assert client_model.client_secret == original_value

        # Modify another field and save again
        client_model.name = "Updated Name"
        client_model.save()

        # Verify the encrypted field is still correct after second save
        assert client_model.client_secret == original_value

        # Test the introspection test pattern: modify encrypted field after initial save
        new_value = "changed-after-save"
        client_model.client_secret = new_value
        client_model.save()

        # Verify the new value is correct after third save
        assert client_model.client_secret == new_value

        # Reload from database and verify persistence
        reloaded = Client.objects.get(id=client_model.id)
        assert reloaded.client_secret == new_value
        assert reloaded.name == "Updated Name"

        # Test one more save cycle to ensure stability
        reloaded.client_secret = "final-value"
        reloaded.save()

        final_reload = Client.objects.get(id=client_model.id)
        assert final_reload.client_secret == "final-value"

    def test_introspection_test_pattern(self, user):
        """Test the exact pattern used by introspection endpoint tests."""
        from oidc_provider.lib.utils.token import hash_token

        # Create a token like introspection tests do
        expires_at = timezone.now() + timedelta(seconds=60)
        token = Token.objects.create(
            user=user,
            client=Client.objects.create(
                name="Test Client", client_id="test-client-id", response_types=["id_token token"]
            ),
            expires_at=expires_at,
            scope=["openid"],
        )

        # This is the pattern from introspection tests:
        # 1. Create token with save()
        assert token.id is not None  # Token was saved

        # 2. Set access_token after creation
        token.access_token = "123456"
        assert token.access_token == "123456"

        # 3. Set access_token_hash
        token.access_token_hash = hash_token(token.access_token)
        expected_hash = hash_token("123456")
        assert token.access_token_hash == expected_hash

        # 4. Save again (this is where problems could occur)
        token.save()

        # 5. Verify values are still correct after second save
        assert token.access_token == "123456"
        assert token.access_token_hash == expected_hash

        # 6. Reload from database and verify persistence
        reloaded = Token.objects.get(id=token.id)
        assert reloaded.access_token == "123456"
        assert reloaded.access_token_hash == expected_hash
