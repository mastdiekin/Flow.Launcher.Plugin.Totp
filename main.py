# Author: Dmitriy Surkov
# Github: @mastdiekin
# Description: Flow Launcher TOTP Generator
# Date: 2024-11-08

import sys
from pathlib import Path

plugindir = Path.absolute(Path(__file__).parent)
paths = (".", "lib", "plugin")
sys.path = [str(plugindir / p) for p in paths] + sys.path

# app
from plugin import plugin


plugin.run()
