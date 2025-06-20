from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
class AESEncryptor:
    def __init__(self, passphrase):
        self.key = self._generate_key(passphrase)

    @staticmethod
    def _generate_key(passphrase):
        """Generate a consistent AES key from a passphrase"""
        return hashlib.sha256(passphrase.encode()).digest()[:16]

    def encrypt(self, message):
        """Encrypt message using AES-CBC"""
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        return cipher.iv + ct_bytes  # Return IV + ciphertext

    def decrypt(self, ciphertext):
        """Decrypt message using AES-CBC"""
        iv = ciphertext[:16]  # Extract IV
        ct = ciphertext[16:]  # Extract ciphertext
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode()