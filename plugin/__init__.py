import time
import pyotp

# libs
from plugin.lib import Totp, Crypt, copy_to_clipboard
from plugin.lib.definitions import APP_ICON, ERROR_ICON

# types
from typing import Union, List

# flow
from pyflowlauncher import Plugin, Result, send_results
from pyflowlauncher.result import ResultResponse

plugin = Plugin()

# @plugin.on_method
# def context_menu(context_data):
#     return send_results([
#         Result(
#             Title="Test",
#             SubTitle="12345",
#             IcoPath=APP_ICON
#         )
#     ])


@plugin.on_method
def query(query: str) -> ResultResponse:
    results: Union[List[Result], List] = []
    search_query = query.strip()
    try:
        app = Totp(settings=plugin.settings)
    except:
        results.append(
            Result(
                Title=f"Something wrong!",
                SubTitle=f"Something wrong with Totp.app",
                IcoPath=ERROR_ICON,
            )
        )
        return send_results(results)

    if len(app.otp_data.entries) > 0:
        for totp_entry in app.otp_data.entries:
            if search_query and search_query.lower() not in totp_entry.name.lower():
                continue

            try:
                key = Crypt.decrypt_key(totp_entry.key)
            except:
                results.append(
                    Result(
                        Title=f"Something wrong!",
                        SubTitle=f"With decrypt '{totp_entry.key}' key!",
                        IcoPath=ERROR_ICON,
                    )
                )
                return send_results(results)

            if not app.check_key_valid(key):
                results.append(
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
                results.append(
                    Result(
                        Title=f"{totp.now()} - {totp_entry.name}",
                        SubTitle=f"Copy to clipboard - Expires in {remaining_seconds}s",
                        IcoPath=APP_ICON,
                        JsonRPCAction={
                            "Method": "copy_to_clipboard",
                            "Parameters": [totp.now()]
                        }
                    )
                )
    else:
        results.append(
            Result(
                Title=f"OTPList is empty!",
                SubTitle="Check OTPList.json for 'entries', or setup migrations links in settings of the plugin!",
                IcoPath=ERROR_ICON,
            )
        )

    return send_results(results)


plugin.add_method(copy_to_clipboard)
