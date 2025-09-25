# Test file for EncryptedTextField dumpdata/loaddata functionality
import json
import tempfile
from io import StringIO
from pathlib import Path

import pytest
from django.core.management import call_command

from oidc_provider.tests.app.encrypted_field_test_app.models import ExampleModel


@pytest.fixture
def example_data():
    return {
        "name": "Test Name",
        "secret": "super_secret_value",
        "created": "2023-01-01",
    }


@pytest.mark.django_db(transaction=True)
def test_dumpdata_creates_valid_json_with_encrypted_field(example_data):
    """Test that dumpdata properly serializes encrypted fields."""
    # Create an object with encrypted secret
    ExampleModel.objects.create(**example_data)

    # Dump the data
    out = StringIO()
    call_command("dumpdata", "encrypted_field_test_app.ExampleModel", stdout=out)

    # Parse the dumped JSON
    dumped_data = json.loads(out.getvalue())

    # Should have one object
    assert len(dumped_data) == 1

    obj = dumped_data[0]
    assert obj["model"] == "encrypted_field_test_app.examplemodel"

    # The secret should be dumped as encrypted metadata (not plaintext)
    secret_field = obj["fields"]["secret"]

    # Verify it's encrypted metadata, not plaintext
    assert isinstance(secret_field, dict), (
        f"Expected dict (encrypted metadata), got {type(secret_field)}: {secret_field}"
    )

    # Should have encryption metadata keys
    assert "ciphertext" in secret_field, f"Missing 'ciphertext' in {secret_field}"
    assert "kid" in secret_field, f"Missing 'kid' in {secret_field}"
    assert "alg" in secret_field, f"Missing 'alg' in {secret_field}"

    # Should NOT contain plaintext
    assert "plaintext" not in secret_field, (
        f"Plaintext should not be in dumped data: {secret_field}"
    )
    assert secret_field != "super_secret_value", f"Should not dump plaintext: {secret_field}"

    # Other fields should be normal
    assert obj["fields"]["name"] == "Test Name"
    assert obj["fields"]["created"] == "2023-01-01"


@pytest.mark.django_db(transaction=True)
def test_loaddata_with_plaintext_fixture():
    """Test loading fixture that contains plaintext (not encrypted) secrets."""
    # Create fixture with plaintext secret
    plaintext_fixture = [
        {
            "model": "encrypted_field_test_app.examplemodel",
            "pk": 1,
            "fields": {
                "name": "Plaintext Name",
                "secret": "plaintext_secret_value",  # Raw string, not encrypted
                "created": "2023-01-01",
            },
        }
    ]

    # Write to temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(plaintext_fixture, f)
        fixture_path = f.name

    try:
        # Load the fixture
        call_command("loaddata", fixture_path)

        # Verify the object was created and secret is handled correctly
        assert ExampleModel.objects.count() == 1
        obj = ExampleModel.objects.first()

        assert obj.name == "Plaintext Name"
        assert obj.secret == "plaintext_secret_value"
        assert str(obj.created) == "2023-01-01"

    finally:
        Path(fixture_path).unlink()


@pytest.mark.django_db(transaction=True)
def test_dumpdata_loaddata_roundtrip(example_data):
    """Test complete dumpdata/loaddata roundtrip preserves encrypted data correctly."""
    # Create original object
    original = ExampleModel.objects.create(**example_data)
    original_secret = original.secret  # This should be the plaintext

    # Dump the data
    out = StringIO()
    call_command("dumpdata", "encrypted_field_test_app.ExampleModel", stdout=out)
    dumped_json = out.getvalue()

    # Verify the dump contains encrypted metadata
    dumped_data = json.loads(dumped_json)
    secret_field = dumped_data[0]["fields"]["secret"]
    assert isinstance(secret_field, dict)
    assert "ciphertext" in secret_field
    assert secret_field != "super_secret_value"  # Not plaintext

    # Clear the database
    ExampleModel.objects.all().delete()
    assert ExampleModel.objects.count() == 0

    # Load the data back from the dump
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(dumped_json)
        fixture_path = f.name

    try:
        call_command("loaddata", fixture_path)

        # Verify the object was recreated correctly
        assert ExampleModel.objects.count() == 1
        reloaded = ExampleModel.objects.first()

        # The secret should be decrypted correctly
        assert reloaded.secret == original_secret
        assert reloaded.secret == "super_secret_value"
        assert reloaded.name == "Test Name"
        assert str(reloaded.created) == "2023-01-01"

    finally:
        Path(fixture_path).unlink()


@pytest.mark.django_db(transaction=True)
def test_loaddata_with_encrypted_metadata_fixture():
    """Test loading fixture that contains encrypted metadata (as dumped by dumpdata)."""
    # First create a real object to get valid encrypted metadata
    temp_obj = ExampleModel.objects.create(name="Temp", secret="temp_secret", created="2023-01-01")

    # Get the actual encrypted metadata from the database
    db_value = ExampleModel.objects.filter(pk=temp_obj.pk).values_list("secret", flat=True).first()

    # Clean up the temp object
    temp_obj.delete()

    # Now create a fixture with real encrypted metadata
    encrypted_fixture = [
        {
            "model": "encrypted_field_test_app.examplemodel",
            "pk": 1,
            "fields": {
                "name": "Encrypted Name",
                "secret": db_value,  # Real encrypted metadata
                "created": "2023-01-01",
            },
        }
    ]

    # Write to temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(encrypted_fixture, f)
        fixture_path = f.name

    try:
        # This should work - the field should accept encrypted metadata
        call_command("loaddata", fixture_path)

        # Verify the object was created and can be decrypted properly
        assert ExampleModel.objects.count() == 1
        obj = ExampleModel.objects.first()

        assert obj.name == "Encrypted Name"
        assert obj.secret == "temp_secret"  # Should decrypt to original value
        assert str(obj.created) == "2023-01-01"

    finally:
        Path(fixture_path).unlink()
