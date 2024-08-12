import base64
import ctypes
import pyotp

# types
from typing import Tuple

crypt32 = ctypes.WinDLL('crypt32.dll')
kernel32 = ctypes.WinDLL('kernel32.dll')


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ('cbData', ctypes.c_ulong),
        ('pbData', ctypes.POINTER(ctypes.c_ubyte))
    ]


class Crypt:
    """Class for working with encryption and decryption
    """

    @staticmethod
    def encrypt_key(unencrypted: str) -> str:
        """Encrypt a string using the current user account

        Args:
            unencrypted (str): Unencrypted key string

        Returns:
            str: Encoded string
        """
        # Convert the string to bytes
        data = DATA_BLOB(len(unencrypted), ctypes.cast(ctypes.create_string_buffer(
            unencrypted.encode('utf-8')), ctypes.POINTER(ctypes.c_ubyte)))
        encrypted = DATA_BLOB()

        # Call the CryptProtectData function
        if crypt32.CryptProtectData(ctypes.byref(data), None, None, None, None, 0, ctypes.byref(encrypted)):
            # Convert encrypted data to base64 for easy storage
            encrypted_bytes = ctypes.string_at(
                encrypted.pbData, encrypted.cbData)
            kernel32.LocalFree(encrypted.pbData)
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        else:
            raise ctypes.WinError()

    @staticmethod
    def decrypt_key(encrypted: str) -> str:
        """Decrypt a string using the current user account

        Args:
            encrypted (str): Encrypted key string

        Returns:
            str: Decoded string
        """
        encrypted_data = base64.b64decode(encrypted)
        data = DATA_BLOB(len(encrypted_data), ctypes.cast(
            ctypes.create_string_buffer(encrypted_data), ctypes.POINTER(ctypes.c_ubyte)))
        decrypted = DATA_BLOB()

        # Call the CryptUnprotectData function
        if crypt32.CryptUnprotectData(ctypes.byref(data), None, None, None, None, 0, ctypes.byref(decrypted)):
            decrypted_bytes = ctypes.string_at(
                decrypted.pbData, decrypted.cbData)
            kernel32.LocalFree(decrypted.pbData)
            return decrypted_bytes.decode('utf-8')
        else:
            raise ctypes.WinError()

    @staticmethod
    def ecrypt_data(link: str) -> Tuple[str, str]:
        """Encrypt data

        Args:
            link (str): otpauth:// link

        Returns:
            Tuple[str, str]: (enc_key, f"{issuer}:{second_name}")
        """
        totp = pyotp.parse_uri(link)
        issuer = totp.issuer
        name = totp.name
        key = totp.secret

        if not issuer:
            issuer = "<NO NAME>"
        if not name:
            name = "<NO NAME>"

        # we need encrypt key and save it!
        enc_key = Crypt.encrypt_key(key)
        return enc_key, f"{issuer}:{name}"
