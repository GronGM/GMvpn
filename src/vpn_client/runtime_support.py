from __future__ import annotations

from dataclasses import dataclass

from vpn_client.client_platform import ClientPlatform
from vpn_client.models import PlatformCapability, PlatformSupportStatus


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
    platform_capability: PlatformCapability | None = None,
) -> RuntimeSupportAssessment:
    if platform_adapter_name == "simulated":
        return RuntimeSupportAssessment(
            tier="development-only",
            summary="the simulated adapter is intended for modeling, tests, and local dry runs rather than MVP release claims",
            in_mvp_scope=False,
            caveats=[],
        )

    mismatch_caveats: list[str] = []
    if platform_capability is not None:
        if dataplane_name not in platform_capability.supported_dataplanes:
            mismatch_caveats.append(
                f"manifest platform_capabilities for {client_platform.value} do not declare dataplane '{dataplane_name}'"
            )
        if platform_adapter_name != platform_capability.network_adapter:
            mismatch_caveats.append(
                f"manifest platform_capabilities for {client_platform.value} expect network adapter '{platform_capability.network_adapter}', not '{platform_adapter_name}'"
            )

    if client_platform is ClientPlatform.LINUX and dataplane_name == "xray-core" and platform_adapter_name == "linux":
        if platform_capability is not None and platform_capability.status != PlatformSupportStatus.MVP_SUPPORTED.value:
            mismatch_caveats.append(
                "manifest platform_capabilities do not mark the linux xray contour as mvp-supported"
            )
        if mismatch_caveats:
            return RuntimeSupportAssessment(
                tier="contract-mismatch",
                summary="repository MVP contour was selected, but the manifest support contract does not declare the same release contour",
                in_mvp_scope=False,
                caveats=mismatch_caveats,
            )
        return RuntimeSupportAssessment(
            tier="mvp-supported",
            summary="linux desktop-class xray-backed contour is the first honest MVP runtime target",
            in_mvp_scope=True,
            caveats=[],
        )

    if client_platform is ClientPlatform.LINUX and platform_adapter_name == "linux":
        if mismatch_caveats:
            return RuntimeSupportAssessment(
                tier="contract-mismatch",
                summary="selected linux contour does not match the manifest platform capability contract",
                in_mvp_scope=False,
                caveats=mismatch_caveats,
            )
        return RuntimeSupportAssessment(
            tier="foundation-only",
            summary="linux remains the reference runtime, but this exact dataplane contour is outside the first MVP target",
            in_mvp_scope=False,
            caveats=[
                "the first MVP target is the explicit linux + xray-core contour",
            ],
        )

    if client_platform is ClientPlatform.IOS or dataplane_name == "ios-bridge":
        if platform_capability is not None and platform_capability.status not in {
            PlatformSupportStatus.BRIDGE_ONLY.value,
            PlatformSupportStatus.PLANNED.value,
        }:
            mismatch_caveats.append(
                "manifest platform_capabilities should keep ios on a bridge-only or planned track until a real Apple runtime exists"
            )
        return RuntimeSupportAssessment(
            tier="contract-mismatch" if mismatch_caveats else "bridge-only",
            summary="ios stays on a bridge contract track and is not part of the first MVP runtime target",
            in_mvp_scope=False,
            caveats=[
                "the Apple Network Extension runtime is not implemented yet",
                *mismatch_caveats,
            ],
        )

    if client_platform in {ClientPlatform.WINDOWS, ClientPlatform.MACOS, ClientPlatform.ANDROID}:
        return RuntimeSupportAssessment(
            tier="contract-mismatch" if mismatch_caveats else "planned",
            summary="this platform follows the shared xray-oriented product model but remains outside the first hardened MVP runtime target",
            in_mvp_scope=False,
            caveats=[
                "platform adapter behavior is still placeholder-level in this repository",
                *mismatch_caveats,
            ],
        )

    return RuntimeSupportAssessment(
        tier="contract-mismatch" if mismatch_caveats else "development-only",
        summary="this runtime contour is intended for modeling, tests, or local experimentation rather than MVP release claims",
        in_mvp_scope=False,
        caveats=mismatch_caveats,
    )
