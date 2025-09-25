import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.utils.functional import cached_property


class Cipher:
    alg = None

    def __init__(self, kid: str = None):
        self.kid = kid


class PlaintextCipher(Cipher):
    """
    No encryption - plaintext passthrough.
    """

    alg = "plaintext"

    def __init__(self):
        # The plaintext cipher always uses its own fixed kid.
        super().__init__(kid=self.alg)

    def encrypt(self, data: str) -> str:
        return data

    def decrypt(self, ciphertext: str) -> str:
        return ciphertext


class Aes256GcmHkdfCipher(Cipher):
    """
    AES-256 GCM with HKDF key derivation and 96-bit nonces.
    """

    alg = "aes-256-gcm-hkdf"

    def __init__(self, kid: str, secret_key: str | bytes):
        super().__init__(kid=kid)
        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key

    def encrypt(self, plaintext: str) -> bytes:
        """
        Encrypted data uses the following protocol:
        nonce[12] || payload[length]
        """
        # Generate a random 96-bit IV.
        nonce = os.urandom(12)
        ciphertext = AESGCM(self.data_key).encrypt(
            nonce,
            data=plaintext.encode(),
            associated_data=None,
        )
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes) -> str:
        # Begin by fetching the IV
        nonce = ciphertext[:12]
        # Again cast to bytes because django might return a memoryview
        # and in this case, cryptography requires a bytes object, not byteslike
        payload = bytes(ciphertext[12:])
        return AESGCM(self.data_key).decrypt(nonce, payload, associated_data=None).decode()

    @cached_property
    def data_key(self):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"oidc-provider",
            info=None,
        )
        return hkdf.derive(self.secret_key)


class CipherRegistry(dict):
    def set_encryption_cipher(self, cipher: Cipher):
        """
        Set the cipher that should be used for encryption of new values.
        This also adds the cipher to the registry of available decryption ciphers.
        """
        self.encryption_cipher_kid = cipher.kid
        self.add_cipher(cipher)

    def add_cipher(self, cipher: Cipher):
        """
        Add a cipher that can be used for decryption of existing values.
        """
        if cipher.kid in self:
            raise ValueError(f"Cipher with kid='{cipher.kid}' already exists")
        self[cipher.kid] = cipher

    def pick_cipher(self, kid: str, alg: str = None) -> Cipher:
        """
        Pick the right cipher based on the kid. alg is optional, but should be provided
        to better detect misconfigurations.
        """
        if not (cipher := self.get(kid, None)):
            raise ValueError(f"No cipher found for kid='{kid}'")
        if alg is not None and cipher.alg != alg:
            raise ValueError(
                f"Cipher algorithm mismatch for kid='{kid}': expected '{cipher.alg}', got '{alg}'"
            )
        return cipher

    @property
    def encryption_cipher(self) -> Cipher:
        return self[self.encryption_cipher_kid]


default_registry = CipherRegistry()
default_registry.set_encryption_cipher(PlaintextCipher())
