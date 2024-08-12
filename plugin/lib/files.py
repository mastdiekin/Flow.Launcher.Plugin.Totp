import json

# lib
from plugin.lib.definitions import OTP_CONFIG_PATH, OTP_CONFIG_DEFAULT_DATA
from plugin.lib.models import OtpConfig


class Files:
    @staticmethod
    def read_otp_config() -> dict:
        """Read OTPList.json

        Returns:
            dict: Migration config
        """
        with open(OTP_CONFIG_PATH, "r") as f:
            return json.load(f)

    @staticmethod
    def save_storage(data: OtpConfig):
        """Save current opt config data into otr config json
        """
        with open(OTP_CONFIG_PATH, "w") as f:
            json.dump(data.to_dict(), f, indent=4)

    @staticmethod
    def load_empty_storage_data():
        """If otp config file NOT found, return default OptConfig dataclass

        Returns:
            OtpConfig
        """
        with open(OTP_CONFIG_PATH, "w") as new_config:
            json.dump(OTP_CONFIG_DEFAULT_DATA.to_dict(),
                      new_config, indent=4)
            return OTP_CONFIG_DEFAULT_DATA
