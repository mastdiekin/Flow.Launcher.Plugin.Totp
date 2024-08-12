import os
import base64
import ctypes
import json
import time
import pyotp
import pyperclip
from urllib.parse import urlparse

# libs
from plugin.migration_decoder.decoder import decode
from plugin.lib.models import Entrie, UrlScheme
from plugin.lib.definitions import *

# types
from typing import Union, List, Tuple

# flow
from pyflowlauncher import Plugin, Result, Method
from pyflowlauncher.result import ResultResponse

plugin = Plugin()

crypt32 = ctypes.WinDLL('crypt32.dll')
kernel32 = ctypes.WinDLL('kernel32.dll')


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ('cbData', ctypes.c_ulong),
        ('pbData', ctypes.POINTER(ctypes.c_ubyte))
    ]


class Query(Method):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.settings = plugin.settings
        self.otp_data = self.load_storage()
        self.otpauth_links = []
        self.urls = self.parse_settings_urls()
        self.handle_auth_import(urls=self.urls)

    def __call__(self, query: str) -> ResultResponse:
        search_query = query.strip()
        if len(self.otp_data.entries) > 0:
            for totp_entry in self.otp_data.entries:
                if search_query and search_query.lower() not in totp_entry.name.lower():
                    continue

                try:
                    key = self.decrypt_key(totp_entry.key)
                except:
                    self.add_result(
                        Result(
                            Title=f"Something wrong!",
                            SubTitle=f"With decrypt '{totp_entry.key}' key!",
                            IcoPath=ERROR_ICON,
                        )
                    )
                    return self.return_results()

                if not self.check_key_valid(key):
                    self.add_result(
                        Result(
                            Title=f"{totp_entry.name}: Invalid OTP secret",
                            SubTitle="This OTP contains an invalid OTP secret that can't be decoded as base32 data",
                            IcoPath=ERROR_ICON,
                        )
                    )
                else:
                    totp = pyotp.TOTP(key)
                    remaining_seconds = totp.interval - \
                        int(time.time()) % totp.interval
                    self.add_result(
                        Result(
                            Title=f"{totp.now()} - {totp_entry.name}",
                            SubTitle=f"Copy to clipboard - Expires in {remaining_seconds}s",
                            IcoPath=APP_ICON,
                            JsonRPCAction={
                                "method": self.copy_to_clipboard(text=totp.now()),
                            }
                        )
                    )
        else:
            self.add_result(
                Result(
                    Title=f"OTPList is empty!",
                    SubTitle="Check OTPList.json for 'entries', or setup migrations links in settings of the plugin!",
                    IcoPath=ERROR_ICON,
                )
            )
        return self.return_results()

    def parse_settings_urls(self, ):
        """Parsing migration links from user settings field

        Returns:
            list: Parsed links
        """
        url_string = self.settings.get('otpauthLinks', None)
        if not url_string:
            return None

        data = []
        for i in url_string.split('\n'):
            if not i:
                continue
            data.append(i.strip())
        return data

    def load_empty_storage_data(self, ):
        """If otp config file NOT found, return default OptConfig dataclass

        Returns:
            OtpConfig
        """
        with open(OTP_CONFIG_PATH, "w") as new_config:
            json.dump(OTP_CONFIG_DEFAULT_DATA.to_dict(),
                      new_config, indent=4)
            return OTP_CONFIG_DEFAULT_DATA

    def encrypt_unencripted_data(self, data: list):
        """Propably config json contains unencrypted data, then encrypt it!

        Args:
            data (list): list of entries (not Entrie!)

        Returns:
            list
        """
        unencrypted_links = []
        result = []
        for obj in data:
            if obj.get('is_encrypted'):
                continue
            unencrypted_links.append(obj.get('key'))

        if len(unencrypted_links) < 1:
            return result

        urls_schemes = self.generate_urls_scheme(urls=unencrypted_links)
        otpauth_links = self.generate_otpauth_links(urls=urls_schemes)

        for opt_link in otpauth_links:
            enc_key, name = self.ecrypt_data(link=opt_link)
            result.append({
                "name": name,
                "key": enc_key,
                "is_encrypted": True
            })

        return result

    def load_known_storage_data(self, ):
        """If we found otp config file, read and convert to OtpConfig dataclass. If entries contains unencrypted data, then we resave config json

        Returns:
            OptConfig
        """
        with open(OTP_CONFIG_PATH, "r") as file:
            data = json.load(file)
            data['entries'] += self.encrypt_unencripted_data(
                data=data['entries']
            )
            is_decrypted_exist = False
            unique_entries = {}
            # get only unique encrypted generated entries plus if the data included unencrypted data, we write this to the flag
            for item in data['entries']:
                if item['is_encrypted']:
                    unique_entries[item['name']] = item
                else:
                    is_decrypted_exist = True
            # get only encrypted entries
            unique_encrypted_list = list(unique_entries.values())
            data = OtpConfig(
                version=data['version'],
                entries=[Entrie(**entrie) for entrie in unique_encrypted_list]
            )
            # if we have previously decrypted data, then resave storage with new encrypted data
            if is_decrypted_exist:
                self.save_storage(data=data)
            return data

    def load_storage(self):
        """Load OPT config

        Returns:
            OptConfig
        """
        if not os.path.exists(OTP_CONFIG_PATH):
            return self.load_empty_storage_data()

        return self.load_known_storage_data()

    def save_storage(self, data: OtpConfig):
        """Save current opt config data into otr config json
        """
        with open(OTP_CONFIG_PATH, "w") as file:
            json.dump(data.to_dict(), file, indent=4)

    def encrypt_key(self, unencrypted: str) -> str:
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

    def decrypt_key(self, encrypted: str) -> str:
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

    def check_key_valid(self, key: str):
        """Check if this TOTP key is valid

        Args:
            key (str): key

        Returns:
            bool
        """
        try:
            pyotp.TOTP(key)
            return True
        except:
            return False

    def add_to_list(self, name: str, secret: str):
        """Apply new opt data to entries. Plus save in json file

        Args:
            name (str): Name of key
            secret (str): Secret key
        """
        # Check for a record with the same name
        for entry in self.otp_data.entries:
            if entry.name == name:
                return

        self.otp_data.entries.append(
            Entrie(
                name=name,
                key=secret,
                is_encrypted=True
            )
        )
        self.save_storage(data=self.otp_data)

    def google_migration_decoder(self, url):
        """Google migration link decoder

        Args:
            url (str): Migration link from Google Authentificator

        Returns:
            str: otpauth://... link
        """
        return decode(url)

    def generate_urls_scheme(self, urls: Union[List[str], List]) -> Union[List[UrlScheme], List]:
        """Let's check what type of link was passed by the user

        Args:
            urls (Union[List[str], List]): List of otps links

        Returns:
            Union[List[UrlScheme], List]
        """
        result = []
        for url in urls:
            parsed_url = urlparse(url)
            t = OTP_SCHEME_TO_TYPE.get(parsed_url.scheme)
            if t:
                result.append(UrlScheme(type=t, url=url))

        return result

    def generate_otpauth_links(self, urls: List[UrlScheme]) -> List[str]:
        """We will find all the migration links

        Args:
            urls (List[UrlScheme]): List of "otpauth://" or "otpauth-migration://" links (UrlScheme)

        Returns:
            List[str]: List of parsed migration links. Ex: ["otpauth://...", "otpauth://..."]
        """
        links = []
        # we will find all the links
        for obj in urls:
            _type = obj.type
            url = obj.url
            if _type == 'google':
                links += self.google_migration_decoder(url=url)
            elif _type == 'default':
                links += [url]
            else:
                continue

        return links

    def ecrypt_data(self, link: str) -> Tuple[str, str]:
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
        enc_key = self.encrypt_key(key)
        return enc_key, f"{issuer}:{name}"

    def handle_auth_import(self, urls: Union[str, List]):
        """Get "otpauth://" links and save in config json

        Args:
            urls (Union[List[UrlScheme], List]): Links provided by user from settings
        """
        if not urls:
            return

        urls_schemes = self.generate_urls_scheme(urls=urls)
        otpauth_links = self.generate_otpauth_links(urls=urls_schemes)

        if otpauth_links:
            self.otpauth_links += otpauth_links

        for otpauth_link in self.otpauth_links:
            enc_key, name = self.ecrypt_data(link=otpauth_link)
            self.add_to_list(name=name, secret=enc_key)
            # dec_key = self.decrypt_key(enc_key)
            # totp = pyotp.TOTP(dec_key)
            # print(name, name2, totp.now())

    def copy_to_clipboard(self, text: str):
        """Copy to clipboard

        Args:
            text (str)
        """
        pyperclip.copy(text)


plugin.add_method(Query())
