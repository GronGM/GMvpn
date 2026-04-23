from __future__ import annotations

from enum import Enum


class ClientPlatform(str, Enum):
    SIMULATED = "simulated"
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"


def backend_supported_on_platform(client_platform: ClientPlatform, backend_name: str) -> bool:
    supported = {
        "null": {
            ClientPlatform.SIMULATED,
            ClientPlatform.LINUX,
            ClientPlatform.WINDOWS,
            ClientPlatform.MACOS,
            ClientPlatform.ANDROID,
            ClientPlatform.IOS,
        },
        "ios-bridge": {
            ClientPlatform.SIMULATED,
            ClientPlatform.IOS,
        },
        "linux-userspace": {
            ClientPlatform.SIMULATED,
            ClientPlatform.LINUX,
        },
        "xray-core": {
            ClientPlatform.SIMULATED,
            ClientPlatform.LINUX,
            ClientPlatform.WINDOWS,
            ClientPlatform.MACOS,
            ClientPlatform.ANDROID,
        },
        "routed": {
            ClientPlatform.SIMULATED,
            ClientPlatform.LINUX,
            ClientPlatform.WINDOWS,
            ClientPlatform.MACOS,
            ClientPlatform.ANDROID,
            ClientPlatform.IOS,
        },
    }
    return client_platform in supported.get(backend_name, set())


def default_backend_for_platform(client_platform: ClientPlatform) -> str | None:
    defaults = {
        ClientPlatform.SIMULATED: "xray-core",
        ClientPlatform.LINUX: "linux-userspace",
        ClientPlatform.WINDOWS: "xray-core",
        ClientPlatform.MACOS: "xray-core",
        ClientPlatform.ANDROID: "xray-core",
        ClientPlatform.IOS: "ios-bridge",
    }
    return defaults[client_platform]
