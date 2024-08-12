from plugin.lib.models import OtpConfig

APP_ICON = "Images/app.png"
ERROR_ICON = "Images/error.png"

OTP_CONFIG_PATH = "OTPList.json"
"""Migrations list
"""

OTP_CONFIG_DEFAULT_DATA = OtpConfig(version=1)
"""Default empty config data
"""

OTP_SCHEME_TO_TYPE = {
    'otpauth-migration': 'google',
    'otpauth': 'default',
}
"""Opt schemes
"""
