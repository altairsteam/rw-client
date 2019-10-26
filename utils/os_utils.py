import logging
from sys import platform as _platform


def get_operating_system_id():
    return _platform


def get_operating_system_name(os_id):
    if os_id == "linux" or os_id == "linux2":
        return "Linux"
    if os_id == "darwin":
        return "MAC OS X"
    if os_id == "win32":
        return "Windows 32-bits"
    if os_id == "win64":
        return "Windows 64-bits"
