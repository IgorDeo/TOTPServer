from cryptography.fernet import Fernet
import base64
import hmac
import hashlib
import time
import secrets
import os

from dotenv import load_dotenv

load_dotenv()

# In a production environment, this key should be stored securely
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY is not set")

fernet = Fernet(ENCRYPTION_KEY)

HMAC_SECRET_BYTES_LENGTH = 20


def encrypt_secret(secret: str) -> str:
    return fernet.encrypt(secret.encode()).decode()


def decrypt_secret(encrypted_secret: str) -> str:
    return fernet.decrypt(encrypted_secret.encode()).decode()


class TOTP:
    def __init__(self, duration=30, digit_count=6):
        self._duration = duration  # Tempo de duração de cada TOTP (em segundos)
        self._digit_count = digit_count  # Número de dígitos do TOTP

    def generate_secret(self):
        """Gera uma chave secreta em base32."""
        # Gerar a chave em base32 é uma extensão da RFC 4226. Essa codificação é util para tornar o secret mais facilmente digitável.
        secret = base64.b32encode(secrets.token_bytes(HMAC_SECRET_BYTES_LENGTH)).decode(
            "utf-8"
        )
        return secret

    def generate_totp(self, secret):
        """Gera um TOTP com base em um secret fornecido."""
        key = self._decode_secret(secret)
        t = self._calculate_t()
        hash_value = self._generate_hmac(key, t)
        return self._truncate(hash_value)

    def _decode_secret(self, secret):
        """Decodifica um segredo em base32."""
        return base64.b32decode(secret, casefold=True)

    def _calculate_t(self):
        """Calcula o contador de tempo T com base no UNIX time."""
        now = int(time.time())
        return (now // self._duration).to_bytes(8, byteorder="big")

    def _generate_hmac(self, key, t):
        """Gera um hash HMAC com SHA-1."""
        return hmac.new(key, t, hashlib.sha1).digest()

    def _truncate(self, hash_value):
        """Aplica a truncagem ao hash para gerar o TOTP."""
        offset = hash_value[-1] & 0x0F
        extracted_value = (
            int.from_bytes(hash_value[offset : offset + 4], byteorder="big")
            & 0x7FFFFFFF
        )
        otp = extracted_value % (10**self._digit_count)
        return str(otp).zfill(self._digit_count)

    def validate_totp(self, secret, otp, since=None):
        """Valida um TOTP fornecido."""
        generated_otp = self.generate_totp(secret)
        return otp == generated_otp and not self._has_been_used(since)

    def _has_been_used(self, since):
        """Verifica se um TOTP foi usado em um intervalo de tempo."""
        if since is None:
            return False
        now = int(time.time())
        return now // self._duration <= since // self._duration
