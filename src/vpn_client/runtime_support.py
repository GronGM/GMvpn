from __future__ import annotations

from dataclasses import dataclass

from vpn_client.client_platform import ClientPlatform


@dataclass(slots=True)
class RuntimeSupportAssessment:
    tier: str
    summary: str
    in_mvp_scope: bool
    caveats: list[str]


def assess_runtime_support(
    *,
    client_platform: ClientPlatform,
    dataplane_name: str,
    platform_adapter_name: str,
) -> RuntimeSupportAssessment:
    if client_platform is ClientPlatform.LINUX and dataplane_name == "xray-core" and platform_adapter_name == "linux":
        return RuntimeSupportAssessment(
            tier="mvp-supported",
            summary="linux desktop-class xray-backed contour is the first honest MVP runtime target",
            in_mvp_scope=True,
            caveats=[],
        )

    if client_platform is ClientPlatform.LINUX and platform_adapter_name == "linux":
        return RuntimeSupportAssessment(
            tier="foundation-only",
            summary="linux remains the reference runtime, but this exact dataplane contour is outside the first MVP target",
            in_mvp_scope=False,
            caveats=[
                "the first MVP target is the explicit linux + xray-core contour",
            ],
        )

    if client_platform is ClientPlatform.IOS or dataplane_name == "ios-bridge":
        return RuntimeSupportAssessment(
            tier="bridge-only",
            summary="ios stays on a bridge contract track and is not part of the first MVP runtime target",
            in_mvp_scope=False,
            caveats=[
                "the Apple Network Extension runtime is not implemented yet",
            ],
        )

    if client_platform in {ClientPlatform.WINDOWS, ClientPlatform.MACOS, ClientPlatform.ANDROID}:
        return RuntimeSupportAssessment(
            tier="planned",
            summary="this platform follows the shared xray-oriented product model but remains outside the first hardened MVP runtime target",
            in_mvp_scope=False,
            caveats=[
                "platform adapter behavior is still placeholder-level in this repository",
            ],
        )

    return RuntimeSupportAssessment(
        tier="development-only",
        summary="this runtime contour is intended for modeling, tests, or local experimentation rather than MVP release claims",
        in_mvp_scope=False,
        caveats=[],
    )
