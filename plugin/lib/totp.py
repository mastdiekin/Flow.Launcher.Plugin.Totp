import os
import pyotp
from urllib.parse import urlparse

# libs
from plugin.lib import Crypt, Files
from plugin.lib.models import Entrie, UrlScheme, OtpConfig
from plugin.lib.definitions import OTP_CONFIG_PATH, OTP_SCHEME_TO_TYPE
from plugin.migration_decoder.decoder import decode

# types
from typing import Union, List

# flow
from pyflowlauncher import Plugin


class Totp:
    def __init__(self, settings: Plugin.settings):
        """Main plugin class

        Args:
            settings (pyflowlauncher.Plugin().settings): Plugin settings
        """
        self.settings = settings
        self.run()

    def run(self, ):
        """Load storage, parse settings, etc...
        """
        self.otp_data = self.load_storage()
        self.otpauth_links = []
        self.urls = self.parse_settings_urls()
        self.handle_auth_import(urls=self.urls)

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
            enc_key, name = Crypt.ecrypt_data(link=opt_link)
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
        is_unencrypted_exist = False
        data = Files.read_otp_config()
        data['entries'] += self.encrypt_unencripted_data(
            data=data['entries']
        )
        unique_entries = {}
        # get only unique encrypted generated entries plus if the data included unencrypted data, we write this to the flag
        for item in data['entries']:
            if item['is_encrypted']:
                unique_entries[item['name']] = item
            else:
                is_unencrypted_exist = True
        # get only encrypted entries
        unique_encrypted_list = list(unique_entries.values())
        data = OtpConfig(
            version=data['version'],
            entries=[Entrie(**entrie) for entrie in unique_encrypted_list]
        )

        # if we have previously decrypted data, then resave storage with new encrypted data
        if is_unencrypted_exist:
            Files.save_storage(data=data)
        return data

    def load_storage(self):
        """Load OPT config

        Returns:
            OptConfig
        """
        if not os.path.exists(OTP_CONFIG_PATH):
            return Files.load_empty_storage_data()

        return self.load_known_storage_data()

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
        Files.save_storage(data=self.otp_data)

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
            enc_key, name = Crypt.ecrypt_data(link=otpauth_link)
            self.add_to_list(name=name, secret=enc_key)
