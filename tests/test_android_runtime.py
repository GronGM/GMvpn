from __future__ import annotations

import json
import unittest

from vpn_client.android_runtime import (
    AndroidRuntimeState,
    build_android_runtime_request,
    build_initial_android_runtime_status,
    render_android_runtime_request_json,
    validate_android_runtime_endpoint_metadata,
)
from vpn_client.models import Endpoint, NetworkPolicy


class AndroidRuntimeContractTests(unittest.TestCase):
    def test_build_android_runtime_request(self) -> None:
        endpoint = Endpoint(
            id="spb-main-desktop",
            host="198.51.100.40",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "logical_server": "spb-main",
                "supported_client_platforms": ["android"],
                "dataplane": "xray-core",
                "android_policy": {
                    "session_name": "SPB Main",
                    "protect_socket_api": True,
                    "meter_handling": "allow_metered",
                    "on_boot_reconnect": True,
                    "rank_priority": 10,
                },
            },
        )

        request = build_android_runtime_request(endpoint, network_policy=NetworkPolicy())

        self.assertEqual(request.schema_version, 1)
        self.assertEqual(request.request_kind, "start_vpn_service")
        self.assertEqual(request.config.session_name, "SPB Main")
        self.assertEqual(request.config.dataplane_backend, "xray-core")
        self.assertEqual(request.lifecycle["on_boot_reconnect"], True)

    def test_initial_android_runtime_status(self) -> None:
        endpoint = Endpoint(
            id="spb-main-desktop",
            host="198.51.100.40",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "supported_client_platforms": ["android"],
                "dataplane": "xray-core",
                "android_policy": {"session_name": "SPB Main"},
            },
        )

        request = build_android_runtime_request(endpoint)
        status = build_initial_android_runtime_status(request)

        self.assertEqual(status.state, AndroidRuntimeState.PERMISSION_REQUIRED.value)
        self.assertFalse(status.vpn_prepared)
        self.assertFalse(status.backend_started)

    def test_render_request_json(self) -> None:
        endpoint = Endpoint(
            id="spb-main-desktop",
            host="198.51.100.40",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "supported_client_platforms": ["android"],
                "dataplane": "xray-core",
                "android_policy": {"session_name": "SPB Main"},
            },
        )

        payload = json.loads(render_android_runtime_request_json(endpoint))

        self.assertEqual(payload["request_kind"], "start_vpn_service")
        self.assertEqual(payload["config"]["session_name"], "SPB Main")

    def test_validate_android_runtime_requires_session_name(self) -> None:
        endpoint = Endpoint(
            id="spb-main-desktop",
            host="198.51.100.40",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "supported_client_platforms": ["android"],
                "android_policy": {"meter_handling": "allow_metered"},
            },
        )

        with self.assertRaises(Exception):
            validate_android_runtime_endpoint_metadata(endpoint)
