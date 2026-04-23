from enum import Enum

class PlatformTarget(str, Enum):
    WINDOWS = "windows"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"

class EngineMode(str, Enum):
    XRAY_PROCESS = "xray_process"
    IOS_NETWORK_EXTENSION = "ios_network_extension"
