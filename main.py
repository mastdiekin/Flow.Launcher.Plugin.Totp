# Author: Dmitriy Surkov
# Github: @mastdiekin
# Description: Flow Launcher TOTP Generator
# Date: 2024-11-08

import sys
import os

parent_folder_path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(parent_folder_path)
sys.path.append(os.path.join(parent_folder_path, 'lib'))
sys.path.append(os.path.join(parent_folder_path, 'plugin'))

# app
from plugin.totp import plugin


plugin.run()
