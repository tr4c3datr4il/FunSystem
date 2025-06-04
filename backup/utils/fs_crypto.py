from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from hashlib import sha256, md5


class FS_Crypto:
    """Encryption and Decryption class. It also hashes data using MD5."""

    # derive aes key and aes nonce from password and salt
    @staticmethod
    def derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
        blob = PBKDF2(password, salt, dkLen=44, count=iterations, hmac_hash_module=SHA256)
        return blob[:32], blob[32:]
    
    # AES GCM encryption
    @staticmethod
    def encrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return tag + ciphertext
    
    # AES GCM decryption
    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes, nonce: bytes) -> bytes:
        tag = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        return cipher.decrypt_and_verify(ciphertext, tag)
    
    # hash data using MD5
    @staticmethod
    def get_hash(data: bytes) -> str:
        return md5(data).hexdigest()