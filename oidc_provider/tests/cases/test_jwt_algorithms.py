"""
Tests for JWT algorithm support (RS256 and HS256) in encode_id_token and decode_id_token functions.
"""

from django.core.management import call_command
from django.test import TestCase

from oidc_provider.lib.utils.token import create_id_token
from oidc_provider.lib.utils.token import decode_id_token
from oidc_provider.lib.utils.token import encode_id_token
from oidc_provider.tests.app.utils import create_fake_client
from oidc_provider.tests.app.utils import create_fake_user


class JWTAlgorithmTestCase(TestCase):
    """Test JWT algorithm support for both RS256 and HS256."""

    def setUp(self):
        call_command("creatersakey")
        self.user = create_fake_user()

    def test_encode_decode_id_token_rs256(self):
        """Test that RS256 JWT encoding and decoding works correctly."""
        # Create client with RS256 (default)
        client = create_fake_client("code")
        self.assertEqual(client.jwt_alg, "RS256")

        # Create ID token payload
        id_token_payload = create_id_token(
            token=None, user=self.user, aud=client.client_id, request=None, scope=["openid"]
        )

        # Encode the token
        jwt_token = encode_id_token(id_token_payload, client)
        self.assertIsInstance(jwt_token, str)
        self.assertTrue(jwt_token.startswith("eyJ"))  # JWT header starts with eyJ

        # Decode the token
        decoded_payload = decode_id_token(jwt_token, client)
        self.assertEqual(decoded_payload["aud"], client.client_id)
        self.assertEqual(decoded_payload["sub"], str(self.user.id))

    def test_encode_decode_id_token_hs256(self):
        """Test that HS256 JWT encoding and decoding works correctly."""
        # Create client with HS256
        client = create_fake_client("code")
        client.jwt_alg = "HS256"
        client.save()

        # Create ID token payload
        id_token_payload = create_id_token(
            token=None, user=self.user, aud=client.client_id, request=None, scope=["openid"]
        )

        # Encode the token
        jwt_token = encode_id_token(id_token_payload, client)
        self.assertIsInstance(jwt_token, str)
        self.assertTrue(jwt_token.startswith("eyJ"))  # JWT header starts with eyJ

        # Decode the token
        decoded_payload = decode_id_token(jwt_token, client)
        self.assertEqual(decoded_payload["aud"], client.client_id)
        self.assertEqual(decoded_payload["sub"], str(self.user.id))

    def test_unsupported_algorithm_raises_exception(self):
        """Test that unsupported algorithms raise an exception."""
        client = create_fake_client("code")
        client.jwt_alg = "ES256"  # Unsupported algorithm
        client.save()

        id_token_payload = create_id_token(
            token=None, user=self.user, aud=client.client_id, request=None, scope=["openid"]
        )

        with self.assertRaises(Exception) as context:
            encode_id_token(id_token_payload, client)

        self.assertIn("Unsupported key algorithm", str(context.exception))

    def test_rs256_vs_hs256_produce_different_tokens(self):
        """Test that RS256 and HS256 produce different tokens for the same payload."""
        # Create two clients with different algorithms
        rs256_client = create_fake_client("code")
        hs256_client = create_fake_client("code")
        hs256_client.jwt_alg = "HS256"
        hs256_client.save()

        # Create the same payload for both
        id_token_payload = create_id_token(
            token=None, user=self.user, aud="test-audience", request=None, scope=["openid"]
        )

        # Encode with both algorithms
        rs256_token = encode_id_token(id_token_payload, rs256_client)
        hs256_token = encode_id_token(id_token_payload, hs256_client)

        # Tokens should be different (different algorithms, different keys/secrets)
        self.assertNotEqual(rs256_token, hs256_token)

        # But both should decode to similar payloads (different signing algorithm headers)
        rs256_decoded = decode_id_token(rs256_token, rs256_client)
        hs256_decoded = decode_id_token(hs256_token, hs256_client)

        # Core claims should be the same
        self.assertEqual(rs256_decoded["aud"], hs256_decoded["aud"])
        self.assertEqual(rs256_decoded["sub"], hs256_decoded["sub"])

    def test_rs256_key_rollover(self):
        """Test that decode_id_token can verify tokens signed with older keys during key rollover."""
        from django.core.management import call_command

        # Create client with RS256
        client = create_fake_client("code")
        self.assertEqual(client.jwt_alg, "RS256")

        # Create ID token payload
        id_token_payload = create_id_token(
            token=None, user=self.user, aud=client.client_id, request=None, scope=["openid"]
        )

        # Encode with the first (default) key
        jwt_token_old = encode_id_token(id_token_payload, client)

        # Add a new RSA key (simulating key rollover)
        call_command("creatersakey")

        # The new key should now be first in the queryset
        # But we should still be able to decode the old token
        decoded_payload = decode_id_token(jwt_token_old, client)
        self.assertEqual(decoded_payload["aud"], client.client_id)
        self.assertEqual(decoded_payload["sub"], str(self.user.id))

        # New tokens should be signed with the new (first) key
        jwt_token_new = encode_id_token(id_token_payload, client)
        
        # Both old and new tokens should be decodable
        decoded_old = decode_id_token(jwt_token_old, client)
        decoded_new = decode_id_token(jwt_token_new, client)
        
        self.assertEqual(decoded_old["aud"], decoded_new["aud"])
        self.assertEqual(decoded_old["sub"], decoded_new["sub"])
